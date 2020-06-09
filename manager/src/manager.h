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
    size_t initialServerPoolSize;

    /* Event loop connection polling size (default: 1024) */
    size_t eventPollLimit;

    /* Configuration-driven logging filename */
    char *sessionLogFileName;

    /* Things below here are not directly bound from configuration */

    /* Access logging file information, NULL indicates no logging */
    FILE *sessionLogFile;

    /* Storage element for the profile hash */
    WXHashTable profiles;

    /* Just being sneaky, this flag is only controlled by the signaller */
    int shutdownRequested;
} GlobalConfigType;

extern GlobalConfigType GlobalConfig;

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
                          char *request);

    /* Process an explicit action against the profile/session */
    void (*processAction)(NGXMGR_Profile *profile, NGXModuleConnection *conn,
                          char *request, char *action, char *sessionId,
                          char *data, int dataLen);
};

/* Exposed allocation method for creating profiles instances from config */
NGXMGR_Profile *NGXMGR_AllocProfile(char *profileName, WXJSONValue *config);

#endif
