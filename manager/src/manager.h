/**
 * Shared definitions for the session manager elements.
 *
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#ifndef NGXSESS_MANAGER_H
#define NGXSESS_MANAGER_H 1

#include "socket.h"
#include "event.h"
#include "threadpool.h"
#include "dbxf.h"
#include "json.h"
#include "buffer.h"
#include "hash.h"

/* Might as well include this here */
#include "messages.h"

/* Storage type and global reference to process configuration settings */
typedef struct {
    /* Interface/address to listen for module requests on (default: any) */
    char *svcBindAddr;

    /* Bind port/service for client connections/requests (default: 5344) */
    char *svcBindService;

    /* Initial number of server connections in the event pool (default: 1024) */
    size_t initialEventPoolSize;

    /* Event loop connection polling size (default: 1024) */
    size_t eventPollLimit;

    /* Limits on the worker thread pool for asynchronous event processing 2/8 */
    size_t minThreadPoolWorkers;
    size_t maxThreadPoolWorkers;

    /* Access/authentication information for database management */
    char *dataSourceName;
    char *dbUser, *dbPasswd;

    /* Configuration-driven logging filenames */
    char *pidFileName;
    char *managerLogFileName;
    char *sessionLogFileName;

    /* Session management options */
    size_t sessionIdLen;
    size_t sessionIdleTime;
    size_t sessionLifespan;
    int sessionIPLocked;

    /* ---- */
    /* Things below here are not directly bound from configuration */

    /* Worker threading pool for handling asynchronous requests */
    WXThreadPool *workerThreadPool;

    /* Database connection pool, NULL if no database access is enabled */
    WXDBConnectionPool *dbConnPool;

    /* Access logging file information, NULL indicates no logging */
    FILE *sessionLogFile;

    /* Storage element for the profile hash */
    WXHashTable *profiles;

    /* Just being sneaky, this flag is only controlled by the signaller */
    int shutdownRequested;
} NGXMGRGlobalDataType;

extern NGXMGRGlobalDataType GlobalData;

/*
 * Container element for an instance of a connection from the nginx module.
 */
typedef struct {
    /* Underlying network connection from module */
    WXSocket connectionHandle;

    /* Request header and incoming request length, <= 0 for header read */
    uint8_t requestHeader[4];
    int32_t requestLength;

    /* Inbound and outbound buffering objects */
    WXBuffer request, response;
} NGXModuleConnection;

/* Management methods for the above, from requests.c */
void NGXMGR_AllocateConnection(WXEvent_Registry *registry, WXSocket connHandle,
                               const char *origin);
void NGXMGR_ProcessEvent(NGXModuleConnection *conn, uint32_t events);
void NGXMGR_UpdateEvents(NGXModuleConnection *conn, uint32_t events);
void NGXMGR_DestroyConnection(NGXModuleConnection *conn);

/* And the common response methods (for use by the profiles) */
void NGXMGR_IssueResponse(NGXModuleConnection *conn, uint8_t code,
                          uint8_t *response, uint32_t responseLength);
void NGXMGR_IssueErrorResponse(NGXModuleConnection *conn, uint16_t errorCode,
                               char *title, char *format, ...)
                                    __attribute__((format(__printf__, 4, 5)));

/*
 * Class and base instance structure for a session security profile.
 */
typedef struct NGXMGR_Profile NGXMGR_Profile;
struct NGXMGR_Profile {
    /* The type and instance name for the profile (latter allocated) */
    const char *type;
    const char *name;

    /* Method to (re)initialize a session profile instance */
    NGXMGR_Profile *(*init)(NGXMGR_Profile *orig, const char *profileName,
                            WXJSONValue *config);

    /* Process the outcome of a verify request that is invalid */
    void (*processVerify)(NGXMGR_Profile *profile, NGXModuleConnection *conn,
                          char *sourceIpAddr, char *request);

    /* Process an explicit action against the profile/session */
    void (*processAction)(NGXMGR_Profile *profile, NGXModuleConnection *conn,
                          char *sourceIpAddr, char *request, char *action,
                          char *sessionId, char *data, int dataLen);

    /* Standard profile configurations trail for static initialization */

    /* The default root index to access if the protocol doesn't define it */
    char *defaultIndex;

    /* Option for locking session to a source IP address (|| with global) */
    int sessionIPLocked;
};

/* Exposed allocation method for creating profiles instances from config */
NGXMGR_Profile *NGXMGR_AllocProfile(char *profileName, WXJSONValue *config);

/* Structure for tracking security element lists, for processing and return */
typedef struct WXMLLinkedElement {
    struct WXMLElement *elmnt;
    struct WXMLLinkedElement *nextElmnt;
} WXMLLinkedElement;

/* Batches of methods for managing sessions (finally!) */
void NGXMGR_InitializeSessions();
char *NGXMGR_GenerateSessionId(int idlen);
int NGXMGR_ValidateSession(char *sessionId, char *sourceIpAddr,
                           int profileIPLocked, WXBuffer *attrs);

/* Callback definition for asynchronous session completion */
/* All data is internally managed, this method must not block (under lock) */
typedef void NGXMGR_CompleteSessionHandler(NGXModuleConnection *conn,
                                           char *sessionId,
                                           WXBuffer *attributes,
                                           char *destURL);

void NGXMGR_AllocateNewSession(char *sourceIpAddr, time_t expiry,
                               WXDictionary *attributes, char *destUrl,
                               NGXModuleConnection *conn,
                               NGXMGR_CompleteSessionHandler handler);

#endif
