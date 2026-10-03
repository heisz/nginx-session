/**
 * Shared definitions for the session manager elements.
 *
 * Copyright (C) 2018-2021 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#ifndef NGXSESS_MANAGER_H
#define NGXSESS_MANAGER_H 1

#include "socket.h"
#include "scheduler.h"
#include "dbxf.h"
#include "json.h"
#include "buffer.h"
#include "hash.h"

/* Might as well include this here */
#include "messages.h"

/* Storage type and global reference to process configuration settings */
typedef struct {
    /* Interface/address to listen for requests on (default: 127.0.0.1) */
    char *svcBindAddr;

    /* Bind port/service for client connections/requests (default: 5344) */
    char *svcBindService;

    /* Maximum accepted request size from the module (default: 1MB) */
    size_t maxRequestSize;

    /* Fiber scheduler processor count, zero to default to the CPU count */
    size_t schedulerProcessors;

    /* Access/authentication information for database management */
    char *dataSourceName;
    char *dbUser, *dbPasswd;

    /* Limit on concurrent (fiber) database connections (default: 8) */
    size_t dbMaxConnections;

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

    /* Database connection pool, NULL if no database access is enabled */
    WXDBConnectionPool *dbConnPool;

    /* Access logging file information, NULL indicates no logging */
    FILE *sessionLogFile;

    /* Storage element for the profile hash */
    WXHashTable *profiles;
} NGXMGRGlobalDataType;

extern NGXMGRGlobalDataType GlobalData;

/* Convenience method to write to the session log with timestamp */
void NGXMGR_SessionLog(const char *format, ...)
                             __attribute__((format(__printf__, 1, 2)));

/* (Re)open the session log file (for config reload, lock safe for write) */
void NGXMGR_ReopenSessionLog();

/* Fiber-level access to the global connection pool */
WXDBConnection *NGXMGR_ObtainDBConnection();
void NGXMGR_ReturnDBConnection(WXDBConnection *conn);

/*
 * Container element for an instance of a connection from the nginx module.
 */
typedef struct {
    /* Underlying network connection from module */
    WXSocket connectionHandle;

    /* Request header and incoming request (body) length */
    uint8_t requestHeader[4];
    int32_t requestLength;

    /* Inbound and outbound buffering objects */
    WXBuffer request, response;

    /* Set on unrecoverable (memory) errors, connection is dropped */
    int closeRequested;
} NGXModuleConnection;

/* Management methods for the above, from requests.c */
void NGXMGR_AllocateConnection(WXSocket connHandle, const char *origin);
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

    /* Mapping/lookup object to get extended attributes */
    WXDictionary extAttributes;
};

/* Exposed allocation method for creating profiles instances from config */
NGXMGR_Profile *NGXMGR_AllocProfile(char *profileName, WXJSONValue *config);

/* Reload-safe lookup of the named profile, NULL if not defined */
NGXMGR_Profile *NGXMGR_GetProfile(const char *profileName);

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
/* All data is internally managed, this method must not yield (under lock) */
typedef void NGXMGR_CompleteSessionHandler(NGXModuleConnection *conn,
                                           char *sessionId,
                                           WXBuffer *attributes,
                                           char *destURL);

void NGXMGR_AllocateNewSession(int userId, char *sourceIpAddr, time_t expiry,
                               WXDictionary *attributes, char *destUrl,
                               NGXModuleConnection *conn,
                               NGXMGR_CompleteSessionHandler handler);

#endif
