/**
 * Primary NGINX session management daemon entry point.
 * 
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <stddef.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include "manager.h"
#include "buffer.h"
#include "log.h"
#include "thread.h"
#include "socket.h"
#include "event.h"

/* External declarations for missing header utilities */
void daemonStart(const char *rootDir, const char *appName,
                 const char *pidFile, const char *logFileName,
                  void (*signalHandler)(int));
void daemonStop();

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
        "Copyright (C) 2018-2020, J.M. Heisz.  All rights reserved.\n"
        "See the LICENSE file accompanying the distribution your rights to\n"
        "use this software.\n");
    exit(0);
}

/* For lack of a better location, capture global configuration here */
#ifndef SYSCONF_DIR
#define SYSCONF_DIR "."
#endif
static char *configFileName = SYSCONF_DIR "/ngxsessmgr.cfg";

GlobalConfigType GlobalConfig = {
   /* svcBindAddr = */ NULL /* any */,
   /* svcBindService = */ NULL /* 5344 */,
   /* initialServerPoolSize = */ 1024,
   /* eventPollLimit = */ 1024,
   /* sessionLogFileName = */ NULL,

   /* ---- */

   /* sessionLogFile = */ NULL,
   /* profiles = */ {0, 0, 0, NULL},
   /* shutdownRequested = */ 0
};

static WXJSONBindDefn cfgBindings[] = {
    { "service.bindAddress", WXJSONBIND_STR,
      offsetof(GlobalConfigType, svcBindAddr), FALSE },
    { "service.bindPort", WXJSONBIND_STR,
      offsetof(GlobalConfigType, svcBindService), FALSE },
    { "eventloop.poolSize", WXJSONBIND_SIZE,
      offsetof(GlobalConfigType, initialServerPoolSize), FALSE },
    { "eventloop.pollSize", WXJSONBIND_SIZE,
      offsetof(GlobalConfigType, eventPollLimit), FALSE },
    { "sessionLogFile", WXJSONBIND_STR,
      offsetof(GlobalConfigType, sessionLogFileName), FALSE }
};

#define CFG_COUNT (sizeof(cfgBindings) / sizeof(WXJSONBindDefn))

/* Iteration method to parse profile configuration data */
static int profileParse(WXHashTable *table, void *key, void *object,
                        void *userData) {
    WXJSONValue *config = (WXJSONValue *) object;
    NGXMGR_Profile *profile;

    /* Find existing entry for reload, otherwise init */
    if (GlobalConfig.profiles.entries == NULL) {
        (void) WXHash_InitTable(&(GlobalConfig.profiles), 64);
    }
    profile = (NGXMGR_Profile *) WXHash_GetEntry(&(GlobalConfig.profiles),
                                                 key, WXHash_StrCaseHashFn,
                                                 WXHash_StrCaseEqualsFn);
    if (profile != NULL) {
        /* Note: errors would have logged internally */
        (void) (profile->init)(profile, (char *) key, config);
    } else {
        profile = NGXMGR_AllocProfile((char *) key, config);
        if (profile != NULL) {
            if (!WXHash_InsertEntry(&(GlobalConfig.profiles),
                                    (void *) profile->name, profile,
                                    NULL, NULL, WXHash_StrCaseHashFn,
                                    WXHash_StrCaseEqualsFn)) {
                WXLog_Error("Internal error, failed to store profile data");
            }
        }
        /* Note: errors would have logged internally */
    }

    return 0;
}

/* TODO - move reload into the events thread! */

/**
 * Core function to load (or reload) the configuration information for the
 * manager, from the command line specified configuration file.
 */
static void parseConfiguration() {
    char *ptr, *str, errMsg[1024];
    WXJSONValue *config, *profiles;
    WXBuffer fileContent;
    int fd, inQuote = 0;

    /* Load the contents of the specified filename */
    if ((fd = open(configFileName, O_RDONLY)) < 0) {
        WXLog_Error("Failed to open configuration file %s for reading: %s",
                    configFileName, strerror(errno));
        return;
    }
    if ((WXBuffer_Init(&fileContent, 1024) == NULL) ||
            (WXBuffer_ReadFile(&fileContent, fd, 0) < 0) ||
            (WXBuffer_Append(&fileContent, "\0", 1, TRUE) == NULL)) {
        WXLog_Error("Failed to read configuration file contents");
        WXBuffer_Destroy(&fileContent);
        (void) close(fd);
        return;
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
    /* Really should log something, because it's not going to end well */
    ptr = (char *) fileContent.buffer;
    while (isspace(*ptr)) ptr++;
    if (*ptr == '\0') return;

    /* Parse it and then use the JSON binding routines to translate root */
    if ((config = WXJSON_Decode((const char *) fileContent.buffer)) == NULL) {
        WXLog_Error("Failed to parse configuration data (mem error)");
        return;
    }
    if (config->type == WXJSONVALUE_ERROR) {
        WXLog_Error("Failed to parse configuration: line %d: %s",
                    config->value.error.lineNumber,
                    WXJSON_GetErrorStr(config->value.error.errorCode));
        WXJSON_Destroy(config);
        return;
    }
    WXBuffer_Destroy(&fileContent);

    if (!WXJSON_Bind(config, &GlobalConfig, cfgBindings, CFG_COUNT,
                     errMsg, sizeof(errMsg))) {
        WXLog_Error("Configuration binding error: %s", errMsg);
        WXJSON_Destroy(config);
        return;
    }

    /* Reset logging */
    if (GlobalConfig.sessionLogFile != NULL) {
        (void) fclose(GlobalConfig.sessionLogFile);
        GlobalConfig.sessionLogFile = NULL;
    }
    if (GlobalConfig.sessionLogFileName != NULL) {
        GlobalConfig.sessionLogFile =
                         fopen(GlobalConfig.sessionLogFileName, "a");
        if (GlobalConfig.sessionLogFile == NULL) {
            WXLog_Error("Unable to open logging file: %s", strerror(errno));
        }
    }

    /* (Re)build the hash of profiles */
    profiles = WXJSON_Find(config, "profiles");
    if ((profiles == NULL) || (profiles->type != WXJSONVALUE_OBJECT)) {
        WXLog_Error("Missing or invalid object for 'profiles' entry");
    } else {
        (void) WXHash_Scan(&(profiles->value.oval), profileParse, NULL);
    }

    WXJSON_Destroy(config);
}

/* Handle signals according to daemon operations */
void coreSignalHandler(int sig) {
    /* All good things must come to an end... */
    if ((sig == SIGINT) || (sig == SIGTERM)) {
        WXLog_Info("NGINX session manager process exiting...");
        GlobalConfig.shutdownRequested = TRUE;
    }

    /* Reconfiguration signal... */
    if (sig == SIGHUP) {
        WXLog_Info("NGINX session manager reloading configuration...");
        parseConfiguration();
    }
}

/* Just keep things tidy */
static int processRequests(WXSocket svcConnectHandle);

/**
 * Where all of the fun begins!
 */
int main(int argc, char **argv) {
    int rc, idx, daemonMode = -1, cnt;
    char *rootDir = NULL, *svc;
    WXSocket svcConnectHandle;

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
    parseConfiguration();

    /* Switch to a daemon, unless indicated otherwise */
    if (daemonMode) {
        daemonStart(rootDir, "SMGR", "/var/run/sessmgr.pid",
                    "/var/log/sessmgr.log", coreSignalHandler);
    } else {
        WXLog_Init("SMGR", NULL);
    }

    /* Mark the process start in the log */
    WXLog_Info("NGINX session manager process starting...");
    WXLog_Info("Build: %s%s%s", CONFIGUREDATE,
               ((strlen(BUILDLABEL) == 0) ? "" : " - "),
               BUILDLABEL);

    /* Open the bind socket, must be exclusive access */
    svc = (GlobalConfig.svcBindService == NULL) ? "5344" :
                                                  GlobalConfig.svcBindService;
    WXLog_Info("Listening on %s:%s for incoming requests",
               ((GlobalConfig.svcBindAddr == NULL) ? "any" :
                                                     GlobalConfig.svcBindAddr),
               svc);
    if (WXSocket_OpenTCPServer(GlobalConfig.svcBindAddr, svc,
                               &svcConnectHandle) != WXNRC_OK) {
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

    /* Hand off to the request handler, returns on exit */
    rc = processRequests(svcConnectHandle);

    /* All done, tidy up... */
    daemonStop();
    return rc;
}

/* Ideally, larger than the number of external connections, plus one */
#define MAX_EVENTS 1024

/* Core event loop registry, plus callback for manipulating it from requests */
static WXEvent_Registry *evtRegistry;
static WXThread_Mutex registryLock = WXTHREAD_MUTEX_STATIC_INIT;
void NGXMGR_UpdateEvents(NGXModuleConnection *conn, uint32_t events) {
    int rc;

    if ((rc = WXThread_MutexLock(&registryLock)) != WXTRC_OK) {
        WXLog_Error("Failed to lock registry mutex: %d", rc);
        /* Carry on, this should never happen unless things are realllly bad */
    }

    /* Handle special signal for connection closure */
    if ((events & WXEVENT_CLOSE) != 0) {
        if ((rc = WXEvent_UnregisterEvent(evtRegistry,
                                         conn->connectionHandle)) != WXNRC_OK) {
            WXLog_Error("Failed to unregister connection: %d", rc);
        }
    } else {
        if ((rc = WXEvent_UpdateEvent(evtRegistry, conn->connectionHandle,
                                      events)) != WXNRC_OK) {
            WXLog_Error("Failed to update connection events: %d", rc);
        }
    }

    if ((rc = WXThread_MutexUnlock(&registryLock)) != WXTRC_OK) {
        WXLog_Error("Failed to unlock registry mutex: %d", rc);
    }
}

/**
 * For tidiness, split the main request handler out from the main() method.
 * Basically runs forever (or until signalled otherwise) waiting for requests
 * from the nginx module.
 *
 * @param svcConnectHandle The bind socket handle established during process
 *                          startup (connections from the nginx module).
 */
static int processRequests(WXSocket svcConnectHandle) {
    WXEvent *event, *eventBuffer;
    WXEvent_UserData data;
    WXSocket acceptHandle;
    char acceptAddr[256];
    ssize_t idx, evtCnt;
    int rc;

    /* Create the primary event registry, register for binding */
    if (WXEvent_CreateRegistry(GlobalConfig.initialServerPoolSize,
                               &evtRegistry) != WXNRC_OK) {
        WXLog_Error("Failed to create primary event registry: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        return 1;
    }
    data.ptr = NULL;
    if (WXEvent_RegisterEvent(evtRegistry, svcConnectHandle,
                              WXEVENT_IN, data) != WXNRC_OK) {
        WXLog_Error("Failed to register server bind socket for events: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        return 1;
    }

    /* Allocate the configured event processing buffer */
    eventBuffer = (WXEvent *) WXMalloc(GlobalConfig.eventPollLimit *
                                       sizeof(WXEvent));
    if (eventBuffer == NULL)
    {
        WXLog_Error("Failed to allocate event processing buffer");
        return 1;
    }

    /* Process forever, or at least until a signal tells us to stop */
    WXLog_Info("Event loop starting, polling %lld slots, %lld pool size",
               (long long int) GlobalConfig.eventPollLimit,
               (long long int) GlobalConfig.initialServerPoolSize);
    while (GlobalConfig.shutdownRequested == 0) {
        /* Wait for something to happen... */
        evtCnt = WXEvent_Wait(evtRegistry, eventBuffer,
                              GlobalConfig.eventPollLimit, NULL);
        if (evtCnt < 0) {
            WXLog_Error("Error in wait on event action (rc %d): %s",
                        (int) evtCnt,
                        WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));

            /* Don't exit, but don't burn loop either... */
            WXThread_USleep(1000000);
            continue;
        }

        /* What it's all about, process request instances */
        for (idx = 0, event = eventBuffer; idx < evtCnt; idx++, event++) {
            /* Handle incoming connection establish actions */
            /* Note that this loops until accept times out, for multiples */
            while (event->socketHandle == svcConnectHandle) {
                rc = WXSocket_Accept(svcConnectHandle, &acceptHandle,
                                     acceptAddr, sizeof(acceptAddr));
                if (rc == WXNRC_TIMEOUT) break;
                if (rc != WXNRC_OK) {
                    WXLog_Error("Error on incoming client accept: %s",
                               WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
                } else {
                    WXLog_Info("Incoming client connect from %s", acceptAddr);

                    /* Hand off to the request code to manage the connection */
                    NGXMGR_AllocateConnection(evtRegistry, acceptHandle,
                                              acceptAddr);
                }
            }
            if (event->socketHandle == svcConnectHandle) continue;

            /* Otherwise it's a transfer processing event */
            NGXMGR_ProcessEvent((NGXModuleConnection *) event->userData.ptr,
                                event->events);
        }
    }

    return 0;
}
