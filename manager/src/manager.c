/**
 * Primary nginx session management daemon entry point.
 * 
 * Copyright (C) 2018-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "manager.h"
#include "buffer.h"
#include "json.h"
#include "log.h"
#include "thread.h"
#include "socket.h"
#include "event.h"

/* External declarations for missing header utilities */
int daemonStart(const char *rootDir, const char *appName,
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
        "Nginx Session Manager Daemon - v0.1.0\n\n"
        "Copyright (C) 2018-2019, J.M. Heisz.  All rights reserved.\n"
        "See the LICENSE file accompanying the distribution your rights to\n"
        "use this software.\n");
    exit(0);
}

/* For lack of a better location, capture configuration here */
static char *configFileName = "./manager.cfg";
static int svcBindPort = 5344;
static char *svcBindAddr = NULL;

/* Utility method to validate config entries with type validation/logging */
static WXJSONValue *configFindWithType(WXJSONValue *cfg, const char *name,
                                       WXJSONValueType type) {
    WXJSONValue *retval = WXJSON_Find(cfg, name);
    if (retval == NULL) return NULL;
    if (retval->type != type) {
        WXLog_Error("Incorrect configuration data type for '%s'", name);
        return NULL;
    }
    return retval;
}

/**
 * Core function to load (or reload) the configuration information for the
 * manager, from the specified 
 */
static void parseConfiguration() {
    WXJSONValue *config, *val;
    WXBuffer fileContent;
    int fd;

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

    /* And parse it */
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

    /* Loads of lookups and translations follow... */
    val = configFindWithType(config, "bindPort", WXJSONVALUE_INT);
    if (val != NULL) {
        svcBindPort = val->value.ival;
    }
    if (svcBindAddr != NULL) WXFree(svcBindAddr);
    val = configFindWithType(config, "bindAddress", WXJSONVALUE_STRING);
    if (val != NULL) {
        svcBindAddr = WXMalloc(strlen(val->value.sval) + 1);
        if (svcBindAddr != NULL) {
            (void) strcpy(svcBindAddr, val->value.sval);
        }
    } else {
        svcBindAddr = NULL;
    }

    WXJSON_Destroy(config);
}

/* Track for clean shutdown */
static int shutdownRequested = 0;

/* Handle signals according to daemon operations */
void coreSignalHandler(int sig) {
    /* All good things must come to an end... */
    if ((sig == SIGINT) || (sig == SIGTERM)) {
        WXLog_Info("Nginx session manager process exiting...");
        shutdownRequested = TRUE;
    }

    /* Reconfiguration signal... */
    if (sig == SIGHUP) {
        WXLog_Info("Nginx session manager reloading configuration...");
        parseConfiguration();
    }
}

/* Just keep things tidy */
static int processRequests(WXSocket srvrConnectHandle);

/**
 * Where all of the fun begins!
 */
int main(int argc, char **argv) {
    int rc, idx, daemonMode = -1, cnt;
    char *rootDir = NULL, svc[64];
    WXSocket srvrConnectHandle;

   /* Parse the command line arguments (most options come from config file) */
   for (idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-c") == 0) {
            if (idx >= (argc - 1)) {
                fprintf(stderr, "Error: missing -c <file> argument");
                usage(1);
            }
            configFileName = argv[++idx];
        } else if (strcmp(argv[idx], "-h") == 0) {
            usage(0);
        } else if (strcmp(argv[idx], "/?") == 0) {
            usage(0);
        } else if (strcmp(argv[idx], "-r") == 0) {
            if (idx >= (argc - 1)) {
                fprintf(stderr, "Error: missing -r <dir> argument");
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
    WXLog_Info("Nginx session manager process starting...");
    WXLog_Info("Build: %s%s%s", CONFIGUREDATE,
               ((strlen(BUILDLABEL) == 0) ? "" : " - "),
               BUILDLABEL);

    /* Open the bind socket, must be exclusive access */
    WXLog_Info("Listening on %s:%d for incoming requests",
               ((svcBindAddr == NULL) ? "any" : svcBindAddr), svcBindPort);
    (void) sprintf(svc, "%d", svcBindPort);
    if (WXSocket_OpenTCPServer(svcBindAddr, svc,
                               &srvrConnectHandle) != WXNRC_OK) {
        WXLog_Error("Failed to open primary bind socket: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        exit(1);
    }

    /* Force connect socket to non-blocking to cleanly handle multi-connect */
    if (WXSocket_SetNonBlockingState(srvrConnectHandle, TRUE) != WXNRC_OK) {
        WXLog_Error("Unable to unblock primary bind socket: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        exit(1);
    }

    /* Hand off to the request handler, returns on exit */
    rc = processRequests(srvrConnectHandle);

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
 * @param srvrConnectHandle The bind socket handle established during process
 *                          startup (connections from the nginx module).
 */
static int processRequests(WXSocket srvrConnectHandle) {
    WXEvent *event, msgEvents[MAX_EVENTS];
    WXEvent_UserData data;
    WXSocket acceptHandle;
    char acceptAddr[256];
    ssize_t idx, evtCnt;
    int rc;

    /* Create the primary event registry, register for binding */
    if (WXEvent_CreateRegistry(1024, &evtRegistry) != WXNRC_OK) {
        WXLog_Error("Failed to create primary event registry: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        return 1;
    }
    data.ptr = NULL;
    if (WXEvent_RegisterEvent(evtRegistry, srvrConnectHandle,
                              WXEVENT_IN, data) != WXNRC_OK) {
        WXLog_Error("Failed to register server bind socket for events: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        return 1;
    }

    /* Process forever, or at least until a signal tells us to stop */
    while (shutdownRequested == 0) {
        /* Wait for something to happen... */
        evtCnt = WXEvent_Wait(evtRegistry, msgEvents, MAX_EVENTS, NULL);
        if (evtCnt < 0) {
            WXLog_Error("Error in wait on event action (rc %d): %s",
                        (int) evtCnt,
                        WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));

            /* Don't exit, but don't burn loop either... */
            WXThread_USleep(1000000);
            continue;
        }

        /* What it's all about, process request instances */
        for (idx = 0, event = msgEvents; idx < evtCnt; idx++, event++) {
            /* Handle incoming connection establish actions */
            /* Note that this loops until accept times out, for multiples */
            while (event->socketHandle == srvrConnectHandle) {
                rc = WXSocket_Accept(srvrConnectHandle, &acceptHandle,
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
            if (event->socketHandle == srvrConnectHandle) continue;

            /* Otherwise it's a transfer processing event */
            NGXMGR_ProcessEvent((NGXModuleConnection *) event->userData.ptr,
                                event->events);
        }
    }

    return 0;
}
