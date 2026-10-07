/**
 * Primary NGINX session management daemon entry point.
 *
 * Copyright (C) 2018-2026 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include "manager.h"
#include "buffer.h"
#include "log.h"
#include "thread.h"
#include "socket.h"
#include "channel.h"

/**
 * Standard usage/version methods.
 */
static void usage(int errorCode) {
    (void) fprintf(stderr,
        "Usage: manager [options]\n\n"
        "Options:\n"
        "    -c <file> - read configuration from <file>\n"
        "    -h        - display usage information\n"
        "    -r <dir>  - specifies install root <dir>\n"
        "    -t        - runs in test (non-daemon) mode\n"
        "    -v        - display version information\n");
    exit(errorCode);
}
static void version() {
    (void) fprintf(stdout,
        "NGINX Session Manager Daemon - v0.1.0\n\n"
        "Copyright (C) 2018-2026, J.M. Heisz.  All rights reserved.\n"
        "See the LICENSE file accompanying the distribution your rights to\n"
        "use this software.\n");
    exit(0);
}

/* For lack of a better location, capture global config or objects here */
#ifndef SYSCONF_DIR
#define SYSCONF_DIR "."
#endif
static char *configFileName = SYSCONF_DIR "/ngxsessmgr.cfg";

static WXHashTable authProfiles;

NGXMGRGlobalDataType GlobalData = {
    /* svcBindAddr = */ NULL /* 127.0.0.1 */,
    /* svcBindService = */ NULL /* 5344 */,
    /* maxRequestSize = */ 1048576,
    /* schedulerProcessors = */ 0,

    /* dataSourceName = */ NULL,
    /* dbUser = */ NULL,
    /* dbPasswd = */ NULL,
    /* dbMaxConnections = */ 8,

    /* pidFileName = */ NULL,
    /* managerLogFileName = */ NULL,
    /* sessionLogFileName = */ NULL,

    /* sessionIdLen = */ 64,
    /* sessionIdleTime = */ 300,
    /* sessionLifespan = */ 86400,
    /* sessionIPLocked = */ FALSE,

    /* ---- */

    /* dbConnPool = */ NULL,
    /* sessionLogFile = */ NULL,
    /* profiles = */ &authProfiles
};

static WXJSONBindDefn cfgBindings[] = {
    { "service.bindAddress", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, svcBindAddr), FALSE },
    { "service.bindPort", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, svcBindService), FALSE },
    { "service.maxRequestSize", WXJSONBIND_SIZE,
      offsetof(NGXMGRGlobalDataType, maxRequestSize), FALSE },

    { "system.scheduler.processors", WXJSONBIND_SIZE,
      offsetof(NGXMGRGlobalDataType, schedulerProcessors), FALSE },

    { "database.dsn", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, dataSourceName), FALSE },
    { "database.user", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, dbUser), FALSE },
    { "database.password", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, dbPasswd), FALSE },
    { "database.maxConnections", WXJSONBIND_SIZE,
      offsetof(NGXMGRGlobalDataType, dbMaxConnections), FALSE },

    { "session.idLength", WXJSONBIND_SIZE,
      offsetof(NGXMGRGlobalDataType, sessionIdLen), FALSE },
    { "session.idleTime", WXJSONBIND_SIZE,
      offsetof(NGXMGRGlobalDataType, sessionIdleTime), FALSE },
    { "session.lifespan", WXJSONBIND_SIZE,
      offsetof(NGXMGRGlobalDataType, sessionLifespan), FALSE },
    { "session.ipLocked", WXJSONBIND_BOOLEAN,
      offsetof(NGXMGRGlobalDataType, sessionIPLocked), FALSE },

    { "pidFile", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, pidFileName), FALSE },
    { "managerLogFile", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, managerLogFileName), FALSE },
    { "sessionLogFile", WXJSONBIND_STR,
      offsetof(NGXMGRGlobalDataType, sessionLogFileName), FALSE }
};

#define CFG_COUNT (sizeof(cfgBindings) / sizeof(WXJSONBindDefn))

/* Safely support reload of profiles with active connection fibers */
static WXThread_Mutex profilesLock = WXTHREAD_MUTEX_STATIC_INIT;

/*
 * Iteration method to parse profile configuration data. Only adds new or
 * swap-updates existing profiles - leaks on any replacement (orphans old
 * instances which may be in flight).  Need full restart to remove profiles.
 */
static int profileParse(WXHashTable *table, void *key, void *object,
                        void *userData) {
    WXJSONValue *config = (WXJSONValue *) object;
    NGXMGR_Profile *profile;

    /* Always allocate for replacement, old instance retained on error */
    profile = NGXMGR_AllocProfile((char *) key, config);
    if (profile == NULL) return 0;

    /* As mentioned above, will leak on replace.  Small < refcnt complexity */
    (void) WXThread_MutexLock(&profilesLock);
    if (!WXHash_PutEntry(GlobalData.profiles, (void *) profile->name, profile,
                         NULL, NULL, WXHash_StrCaseHashFn,
                         WXHash_StrCaseEqualsFn)) {
        WXLog_Error("Internal error, failed to store profile data");
    }
    (void) WXThread_MutexUnlock(&profilesLock);

    return 0;
}

/* Fiber/thread safe lookup of profile, result safe across or post reload */
NGXMGR_Profile *NGXMGR_GetProfile(const char *profileName) {
    NGXMGR_Profile *profile;

    (void) WXThread_MutexLock(&profilesLock);
    profile = (NGXMGR_Profile *) WXHash_GetEntry(GlobalData.profiles,
                                                 (void *) profileName,
                                                 WXHash_StrCaseHashFn,
                                                 WXHash_StrCaseEqualsFn);
    (void) WXThread_MutexUnlock(&profilesLock);

    return profile;
}

/**
 * Core function to load (or reload) the configuration information for the
 * manager, from the command line specified configuration file.  Returns
 * TRUE on successful load/parse/install, FALSE on error.
 */
static int parseConfiguration(int isReload) {
    char *ptr, *str, errMsg[1024];
    WXJSONValue *config, *profiles;
    WXBuffer fileContent;
    int fd, inQuote = 0;

    /* Load the contents of the specified filename */
    if ((fd = open(configFileName, O_RDONLY)) < 0) {
        WXLog_Error("Failed to open configuration file %s for reading: %s",
                    configFileName, strerror(errno));
        return FALSE;
    }
    if ((WXBuffer_Init(&fileContent, 1024) == NULL) ||
            (WXBuffer_ReadFile(&fileContent, fd, 0) < 0) ||
            (WXBuffer_Append(&fileContent, "\0", 1, TRUE) == NULL)) {
        WXLog_Error("Failed to read configuration file contents");
        WXBuffer_Destroy(&fileContent);
        (void) close(fd);
        return FALSE;
    }
    (void) close(fd); fd = -1;

    /* Remove comments, outside of quoted material */
    ptr = (char *) fileContent.buffer;
    while (*ptr != '\0') {
        if (inQuote != 0) {
            if ((inQuote < 0) && (*ptr == '\'')) inQuote++;
            else if ((inQuote > 0) && (*ptr == '"')) inQuote--;
        } else {
            if (*ptr == '\'') inQuote--;
            else if (*ptr == '"') inQuote++;
            else if (*ptr == '#') {
                /* Chomp the comment but leave the newline for line counting */
                str = strchr(ptr, '\n');
                if (str == NULL) *ptr = '\0';
                else (void) memmove(ptr, str, strlen(str) + 1);
            }
        }
        ptr++;
    }

    /* Trim and exit on empty file (avoids parse error) */
    ptr = (char *) fileContent.buffer;
    while (isspace(*ptr)) ptr++;
    if (*ptr == '\0') {
        WXLog_Error("Configuration file %s is empty", configFileName);
        WXBuffer_Destroy(&fileContent);
        return FALSE;
    }

    /* Parse it and then use the JSON binding routines to translate root */
    config = WXJSON_Decode((const char *) fileContent.buffer);
    WXBuffer_Destroy(&fileContent);
    if (config == NULL) {
        WXLog_Error("Failed to parse configuration data (mem error)");
        return FALSE;
    }
    if (config->type == WXJSONVALUE_ERROR) {
        WXLog_Error("Failed to parse configuration: line %d: %s",
                    config->value.error.lineNumber,
                    WXJSON_GetErrorStr(config->value.error.errorCode));
        WXJSON_Destroy(config);
        return FALSE;
    }

    if (!WXJSON_Bind(config, &GlobalData, cfgBindings, CFG_COUNT,
                     errMsg, sizeof(errMsg))) {
        WXLog_Error("Configuration binding error: %s", errMsg);
        WXJSON_Destroy(config);
        return FALSE;
    }

    /* Reset logging */
    NGXMGR_ReopenSessionLog();

    /* Initialize the profile map on first load */
    if (GlobalData.profiles->entries == NULL) {
        if (!WXHash_InitTable(GlobalData.profiles, 64)) {
            WXLog_Error("Memory failure allocating profile table");
            WXJSON_Destroy(config);
            return FALSE;
        }
    }

    /* (Re)build the hash of profiles */
    profiles = WXJSON_Find(config, "profiles");
    if ((profiles == NULL) || (profiles->type != WXJSONVALUE_OBJECT)) {
        WXLog_Error("Missing or invalid object for 'profiles' entry");
        WXJSON_Destroy(config);
        return FALSE;
    }
    (void) WXHash_Scan(&(profiles->value.oval), profileParse, NULL);
    WXJSON_Destroy(config);

    return TRUE;
}

/* Fiber method to process polled system signals (reconfig and halt) */
static void signalHandler(void *arg) {
    int sigFd = (int) (uintptr_t) arg;
    int rc, sigEvent;

    while (TRUE) {
        /* Wait/read until a signal event is received */
        rc = WXThread_SignalRead(sigFd, &sigEvent);
        if (rc == WXTRC_BUSY) {
            /* Nothing pending, wait for the next one */
            if (GMPS_YieldSocket((WXSocket) sigFd, GMPS_EVT_IN) == 0) {
                WXLog_Error("Unable to wait for process signals, exiting");
                WXThread_DaemonStop();
                exit(1);
            }
            continue;
        }
        if (rc != WXTRC_OK) {
            WXLog_Error("Unable to read process signals: %s",
                        strerror(errno));
            WXThread_DaemonStop();
            exit(1);
        }

        /* All good things must come to an end... */
        if (sigEvent == WXTHREAD_SIG_TERMINATE) {
            WXLog_Info("NGINX session manager process exiting...");
            WXThread_DaemonStop();
            exit(0);
        }

        /* Reconfiguration signal... */
        if (sigEvent == WXTHREAD_SIG_RELOAD) {
            WXLog_Info("NGINX session manager reloading configuration...");
            if (!parseConfiguration(TRUE)) {
                WXLog_Error("Configuration reload failed, prior retained");
            }
        }
    }
}

/* Utility method to safely wait the specified time without blocking fibers */
static void snooze(uint32_t usec) {
    GMPS_EnterSyscall();
    WXThread_USleep(usec);
    GMPS_ExitSyscall();
}

/* Fiber to accept and spawn processor connections from the nginx module */
static void acceptHandler(void *arg) {
    WXSocket svcConnectHandle = (WXSocket) (uintptr_t) arg;
    WXSocket acceptHandle;
    char acceptAddr[256];
    int rc;

    WXLog_Info("Accepting connections, max request size %lld bytes",
               (long long int) GlobalData.maxRequestSize);
    while (TRUE) {
        /* Wait for incoming connection (readability on the connect */
        if (GMPS_YieldSocket(svcConnectHandle, GMPS_EVT_IN) == 0) {
            WXLog_Error("Error in wait on bind socket: %s",
                        WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
            snooze(100000);
            continue;
        }

        /* Accept all pending connections */
        while (TRUE) {
            rc = WXSocket_Accept(svcConnectHandle, &acceptHandle,
                                 acceptAddr, sizeof(acceptAddr));
            if (rc == WXNRC_TIMEOUT) break;
            if (rc != WXNRC_OK) {
                WXLog_Error("Error on incoming client accept: %s",
                            WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));

                /* Stall again, certain errors would spin indefinitely */
                snooze(100000);
                break;
            }

            WXLog_Info("Incoming client connect from %s", acceptAddr);

            /* Allocate a connection to handle requests, spawns a fiber */
            NGXMGR_AllocateConnection(acceptHandle, acceptAddr);
        }
    }
}

/* Thread to periodically handle the netpoll action in the scheduler */
static void *netPollHandler(void *arg) {
    while (TRUE) {
        (void) GMPS_NetPoll(500);
    }

    return NULL;
}

/* Channel to manage database pool turnover (NULL for unlimited) */
static GMPS_Channel *dbChannel = NULL;

/**
 * Obtain a database connection, yielding the fiber (if applicable) if the
 * connection limit has been reached until a release occurs.  Non-fiber access
 * is unbounded.
 */
WXDBConnection *NGXMGR_ObtainDBConnection() {
    WXDBConnection *conn;
    void *val;

    if (GlobalData.dbConnPool == NULL) return NULL;

    /* On fiber, use channel write bounding to yield until slot available */
    if ((dbChannel != NULL) && (GMPS_OnFiber())) {
        if (!GMPS_ChannelSend(dbChannel, NULL)) return NULL;
    }

    /* Grab connection pool instance, release channel slot on error */
    conn = WXDBConnectionPool_Obtain(GlobalData.dbConnPool);
    if ((conn == NULL) && (dbChannel != NULL) && (GMPS_OnFiber())) {
        (void) GMPS_ChannelRecv(dbChannel, &val);
    }

    return conn;
}

/* Return a connection back to the pool, waking pending yield if in fiber */
void NGXMGR_ReturnDBConnection(WXDBConnection *conn) {
    void *val;

    WXDBConnectionPool_Return(conn);
    if ((dbChannel != NULL) && (GMPS_OnFiber())) {
        /* Read on the channel will open a slot for a waiting open */
        (void) GMPS_ChannelRecv(dbChannel, &val);
    }
}

/**
 * Where all of the fun begins!
 */
int main(int argc, char **argv) {
    int rc, idx, daemonMode = -1, procCount, sigFd;
    char *rootDir = NULL, *svc, *addr;
    WXSocket svcConnectHandle;
    WXThread netPollThread;

   /* Parse the command line arguments (most options come from config file) */
   for (idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-c") == 0) {
            if (idx >= (argc - 1)) {
                (void) fprintf(stderr, "Error: missing -c <file> argument\n");
                usage(1);
            }
            configFileName = argv[++idx];
        } else if (strcmp(argv[idx], "-h") == 0) {
            usage(0);
        } else if (strcmp(argv[idx], "/?") == 0) {
            usage(0);
        } else if (strcmp(argv[idx], "-r") == 0) {
            if (idx >= (argc - 1)) {
                (void) fprintf(stderr, "Error: missing -r <dir> argument\n");
                usage(1);
            }
            rootDir = argv[++idx];
        } else if (strcmp(argv[idx], "-t") == 0) {
            daemonMode = FALSE;
        } else if (strcmp(argv[idx], "-v") == 0) {
            version();
        } else {
            (void) fprintf(stderr, "Error: Invalid argument: %s\n", argv[idx]);
            usage(1);
        }
    }

    /* Parse initial configuration details, merge command options */
    if (!parseConfiguration(FALSE)) {
        (void) fprintf(stderr, "Error: unable to load configuration from %s\n",
                       configFileName);
        exit(1);
    }

    /* Switch to a daemon, unless indicated otherwise */
    if (daemonMode) {
        WXThread_DaemonStart(rootDir, "SMGR",
                             ((GlobalData.pidFileName != NULL) ?
                                 GlobalData.pidFileName : "/run/sessmgr.pid"),
                             ((GlobalData.managerLogFileName != NULL) ?
                                 GlobalData.managerLogFileName :
                                 "/var/log/sessmgr.log"),
                             NULL);

        /* Note that daemonizing will have closed the session file */
        NGXMGR_ReopenSessionLog();
    } else {
        WXLog_Init("SMGR", NULL);
    }

    /* Open the pipe for receiving process control signals */
    if (WXThread_SignalInit(&sigFd) != WXTRC_OK) {
        WXLog_Error("Unable to capture process signals: %s", strerror(errno));
        exit(1);
    }

    /* Mark the process start in the log */
    WXLog_Info("NGINX session manager process starting...");
    WXLog_Info("Build: %s%s%s", CONFIGUREDATE,
               ((strlen(BUILDLABEL) == 0) ? "" : " - "),
               BUILDLABEL);
    NGXMGR_SessionLog("Manager restarted");

    /* Open the bind socket, must be exclusive access */
    addr = (GlobalData.svcBindAddr == NULL) ? "127.0.0.1" :
                                                GlobalData.svcBindAddr;
    svc = (GlobalData.svcBindService == NULL) ? "5344" :
                                                  GlobalData.svcBindService;
    WXLog_Info("Listening on %s:%s for incoming requests", addr, svc);
    if (WXSocket_OpenTCPServer(addr, svc, &svcConnectHandle) != WXNRC_OK) {
        WXLog_Error("Failed to open primary bind socket: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        exit(1);
    }

    /* Force connect socket to non-blocking to cleanly handle multi-connect */
    if (WXSocket_SetNonBlockingState(svcConnectHandle, TRUE) != WXNRC_OK) {
        WXLog_Error("Unable to unblock primary bind socket: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        exit(1);
    }

    /* Initiale the fiber scheduling system */
    procCount = (int) GlobalData.schedulerProcessors;
    if (procCount <= 0) {
        procCount = (int) sysconf(_SC_NPROCESSORS_ONLN);
        if (procCount <= 0) procCount = 1;
    }
    WXLog_Info("Fiber scheduler initializing, %d processor(s)", procCount);
    if (!GMPS_SchedulerInit(procCount)) {
        WXLog_Error("Unexpected startup error for the fiber scheduler");
        exit(1);
    }

    /* Register the scheduler async functions for the database on fibers */
    WXDB_SetSocketHandlers(GMPS_SocketWait, GMPS_SocketRelease);

    /* Open the database connection, if defined */
    if (GlobalData.dataSourceName == NULL) {
        WXLog_Info("No database DSN configured, memory managed sessions only!");
    } else {
        GlobalData.dbConnPool =
                  (WXDBConnectionPool *) WXMalloc(sizeof(WXDBConnectionPool));
        if (GlobalData.dbConnPool == NULL) {
            WXLog_Error("Unable to allocate DB connection pool instance");
            exit(1);
        }

        /* Register a wait channel of indicated size for dbconn throttling */
        if (GlobalData.dbMaxConnections != 0) {
            dbChannel = GMPS_ChannelCreate((uint32_t)
                                            GlobalData.dbMaxConnections);
            if (dbChannel == NULL) {
                WXLog_Error("Unable to allocate DB connection throttle");
                exit(1);
            }
        }

        WXLog_Info("Initializing database connection pool (limit %lld)",
                   (long long int) GlobalData.dbMaxConnections);
        rc = WXDBConnectionPool_Init(GlobalData.dbConnPool,
                                     GlobalData.dataSourceName,
                                     GlobalData.dbUser, GlobalData.dbPasswd, 1);

        if (rc == WXDRC_DB_ERROR) {
            WXLog_Error("Pool initialization failed: %s",
                        WXDB_GetLastErrorMessage(GlobalData.dbConnPool));
            WXLog_Info("Presuming transient data condition, ignoring...");
        } else if (rc != WXDRC_OK) {
            WXLog_Error("Internal error creating connection pool: %s",
                        WXDB_GetLastErrorMessage(GlobalData.dbConnPool));
            exit(1);
        }
    }

    /* With that, initialize the session elements */
    NGXMGR_InitializeSessions();

    /* Start the fibers to accept connections and handle signals */
    if (GMPS_Start(acceptHandler,
                   (void *) (uintptr_t) svcConnectHandle) == NULL) {
        WXLog_Error("Failed to start the connection accept fiber");
        exit(1);
    }
    if (GMPS_Start(signalHandler, (void *) (uintptr_t) sigFd) == NULL) {
        WXLog_Error("Failed to start the signal processing fiber");
        exit(1);
    }

    /* Start the scheduler netpoll thread */
    if (WXThread_Create(&netPollThread, netPollHandler, NULL) != WXTRC_OK) {
        WXLog_Error("Failed to create the network polling thread");
        exit(1);
    }

    /* No return, shutdown handled in signal processor */
    GMPS_SchedulerStart();

    return 1;
}
