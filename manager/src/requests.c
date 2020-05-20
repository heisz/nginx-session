/**
 * Methods for handling the various requests to the session manager.
 * 
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <arpa/inet.h>
#include "manager.h"
#include "socket.h"
#include "event.h"
#include "log.h"
#include "mem.h"

/* Define this to trace messaging */
#define NGXMGR_TRACE_MSG 1

/**
 * Allocate and register a new module connection instance for request handling.
 * Note that there is no return from this method, any errors discard (close)
 * the connection instance.
 *
 * @param registry The central event registry for handling state changes.
 * @param connHandle The incoming connection handle.
 * @param origin IP address for the connection as obtained from the accept().
 */
void NGXMGR_AllocateConnection(WXEvent_Registry *registry, WXSocket connHandle,
                               const char *origin) {
    NGXModuleConnection *conn;
    WXEvent_UserData data;

    /* Setup connection instance */
    conn = (NGXModuleConnection *) WXMalloc(sizeof(NGXModuleConnection));
    if (conn == NULL) {
        WXLog_Error("Memory failure allocating module connection instance");
        WXSocket_Close(connHandle);
        return;
    }
    conn->connectionHandle = connHandle;
    conn->requestLength = 0;
    (void) WXBuffer_Init(&(conn->request), 0);
    (void) WXBuffer_Init(&(conn->response), 0);

    /* And register for activity */
    data.ptr = conn;
    if (WXEvent_RegisterEvent(registry, connHandle,
                              WXEVENT_IN, data) != WXNRC_OK) {
        WXLog_Error("Failed to register connection for events");
        WXSocket_Close(connHandle);
        WXFree(conn);
        return;
    }
}

/**
 * A whole lot of cleanup on fatal connection error or closure.
 *
 * @param conn The connection to clean up (fully released).
 */
void NGXMGR_DestroyConnection(NGXModuleConnection *conn) {
    WXBuffer_Destroy(&(conn->request));
    WXBuffer_Destroy(&(conn->response));

    if (conn->connectionHandle != INVALID_SOCKET_FD) {
        WXSocket_Close(conn->connectionHandle);
    }
    WXFree(conn);
}

/**
 * Common method to setup/issue a response for the pending request on the
 * provided connection.
 *
 * @param conn The connection instance to send the response on.
 * @param code The numeric response code for the answer.
 * @param response Binary buffer of the response to issue.
 * @param responseLength Number of bytes in the response to send.
 */
static void NGXMGR_IssueResponse(NGXModuleConnection *conn, uint8_t code,
                                 uint8_t *response, uint32_t responseLength) {
    uint8_t header[4];
    int rc;

#ifdef NGXMGR_TRACE_MSG
    WXLog_Debug("Outgoing response %x, length %d", code, responseLength);
    WXLog_Binary(WXLOG_DEBUG, response, 0, responseLength);
#endif

    /* Assemble the response details */
    *((uint32_t *) header) = htonl(responseLength);
    header[0] = code;

    WXBuffer_Empty(&(conn->response));
    if ((WXBuffer_Append(&(conn->response), header, 4, TRUE) == NULL) ||
            (WXBuffer_Append(&(conn->response), response, responseLength,
                             TRUE) == NULL)) {
        WXLog_Error("Unable to allocate response buffer");
        NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
        NGXMGR_DestroyConnection(conn);
        return;
    }
    WXLog_Binary(WXLOG_DEBUG, conn->response.buffer, 0, conn->response.length);

    /* Attempt a write, resetting flags as required */
    rc = WXSocket_Send(conn->connectionHandle, conn->response.buffer,
                       conn->response.length, 0);
    if (rc < 0) {
        WXLog_Error("Write error for response: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
        NGXMGR_DestroyConnection(conn);
        return;
    }
    conn->response.offset += rc;
    if (conn->response.offset < conn->response.length) {
        NGXMGR_UpdateEvents(conn, WXEVENT_OUT);
    }
}

/* Currently, just present for testing (make large for buffering) */
static char *dataContent = "\0\011text/htmlJeff Wuz Here\n";
static char *errContent = "\01\223Not Allowed!\n";

/**
 * Process an incoming event from the main event loop.
 *
 * @param conn Connection instance that has the event.
 * @param events Bitmask of events that have been received.
 */
void NGXMGR_ProcessEvent(NGXModuleConnection *conn, uint32_t events) {
    int rc;

    /* Flush pending write operations before reading more (shouldn't be any) */
    if ((events & WXEVENT_OUT) != 0) {
        rc = WXSocket_Send(conn->connectionHandle,
                           conn->response.buffer + conn->response.offset,
                           conn->response.length - conn->response.offset, 0);
        if (rc < 0) {
            WXLog_Error("Write error for response: %s",
                        WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
            NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
            NGXMGR_DestroyConnection(conn);
            return;
        }
        conn->response.offset += rc;
        if (conn->response.offset >= conn->response.length) {
            NGXMGR_UpdateEvents(conn, WXEVENT_IN);
        }
        return;
    }

    /* Handle incoming requests from the nginx module */
    if ((events & WXEVENT_IN) != 0) {
        /* Assemble request header to determine body */
        if (conn->requestLength <= 0) {
            rc = WXSocket_Recv(conn->connectionHandle,
                               conn->requestHeader - conn->requestLength,
                               4 + conn->requestLength, 0);
            if (rc < 0) {
                if (rc == WXNRC_DISCONNECT) {
                    if (conn->requestLength == 0) {
                        WXLog_Info("Disconnect from nginx session module");
                    } else {
                        WXLog_Error("Truncated header from session module");
                    }
                } else {
                    WXLog_Error("Read error in request header: %s",
                                WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
                }
                NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
                NGXMGR_DestroyConnection(conn);
                return;
            }
            conn->requestLength -= rc;
            if (conn->requestLength > -4) return;

            /* Process header, command is left as highest-order byte */
            conn->requestLength =
                       ntohl(*((int32_t *) conn->requestHeader)) & 0x00FFFFFF;

#ifdef NGXMGR_TRACE_MSG
            WXLog_Debug("Incoming request %d, length %d",
                        *(conn->requestHeader), conn->requestLength);
#endif

            /* Allocate and prepare to read the body of the request */
            if (WXBuffer_EnsureCapacity(&(conn->request), conn->requestLength,
                                        TRUE) == NULL) {
                WXLog_Error("Unable to allocate request buffer (len %d)",
                            conn->requestLength);
                NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
                NGXMGR_DestroyConnection(conn);
                return;
            }
            conn->request.length = conn->request.offset = 0;
        }

        /* Read until the request body has been received */
        rc = WXSocket_Recv(conn->connectionHandle,
                           conn->request.buffer + conn->request.length,
                           conn->requestLength - conn->request.length, 0);
        if (rc < 0) {
            if (rc == WXNRC_DISCONNECT) {
                WXLog_Error("Truncated request body from session module");
            } else {
                WXLog_Error("Read error in request body: %s",
                            WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
            }
            NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
            NGXMGR_DestroyConnection(conn);
            return;
        }
        conn->request.length += rc;
        if (conn->request.length < conn->requestLength) return;
        conn->requestLength = 0;

#ifdef NGXMGR_TRACE_MSG
        WXLog_Binary(WXLOG_DEBUG, conn->request.buffer, 0,
                     conn->request.length);
#endif

        /* Direct incoming requests appropriately */
        /* For now, just issue responses */
*(conn->request.buffer + 2) = '0';
        switch (*(conn->request.buffer + 2)) {
            case '0':
                NGXMGR_IssueResponse(conn, NGXMGR_SESSION_INVALID, "", 0);
                break;
            case 'a':
                NGXMGR_IssueResponse(conn, NGXMGR_SESSION_CONTINUE, "", 0);
                break;
            case 'b':
                NGXMGR_IssueResponse(conn, NGXMGR_EXTERNAL_REDIRECT,
                                     "https://heisz.org", 17);
                break;
            case 'c':
                NGXMGR_IssueResponse(conn, NGXMGR_CONTENT_RESPONSE,
                                     dataContent, strlen(dataContent + 4) + 4);
                break;
            default:
                NGXMGR_IssueResponse(conn, NGXMGR_ERROR_RESPONSE,
                                     errContent, strlen(errContent + 4) + 4);
                break;
        }
    }
}
