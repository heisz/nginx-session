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
#include "buffer.h"

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

#endif
