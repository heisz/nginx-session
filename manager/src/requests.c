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
 * @param [errorCode] Alternatively, error code for explicit error conditions.
 * @param response Binary buffer of the response to issue.
 * @param responseLength Number of bytes in the response to send.
 */
void NGXMGR_IssueResponse(NGXModuleConnection *conn, uint8_t code,
                          uint8_t *response, uint32_t responseLength) {
    uint8_t header[4];
    int rc;

#ifdef NGXMGR_TRACE_MSG
    WXLog_Debug("Outgoing response %x, length %d", code, responseLength);
#endif

    /* Assemble the response details */
    *((uint32_t *) header) = htonl(responseLength);
    header[0] = code;

    if ((WXBuffer_Append(&(conn->response), header, 4, TRUE) == NULL) ||
            (WXBuffer_Append(&(conn->response), response, responseLength,
                             TRUE) == NULL)) {
        WXLog_Error("Unable to allocate response buffer");
        NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
        NGXMGR_DestroyConnection(conn);
        return;
    }
#ifdef NGXMGR_TRACE_MSG
    WXLog_Binary(WXLOG_DEBUG, conn->response.buffer, 0, conn->response.length);
#endif

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

static char *errorFormat =
                "<html><head><title>%s</title></end><body>%s</body></html>";

void NGXMGR_IssueErrorResponse(NGXModuleConnection *conn, uint16_t errorCode,
                               char *title, char *format, ...) {
    uint8_t header[6], msgBuff[1024];
    WXBuffer buffer;
    int len, rc;
    va_list ap;

#ifdef NGXMGR_TRACE_MSG
    WXLog_Debug("Outgoing error: %d: %s", errorCode, title);
#endif

    /* Format the message content */
    WXBuffer_InitLocal(&buffer, msgBuff, sizeof(msgBuff));
    va_start(ap, format);
    if (WXBuffer_VPrintf(&buffer, format, ap) == NULL) {
        WXLog_Error("Unable to allocate error message content");
        NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
        NGXMGR_DestroyConnection(conn);
        va_end(ap);
        return;
    }
    va_end(ap);

    /* Encode the header, take care regarding HTML length */
    len = strlen(errorFormat) - 4 + strlen(title) + strlen(buffer.buffer) + 2;
    *((uint32_t *) header) = htonl(len);
    *header = NGXMGR_ERROR_RESPONSE;
    *((uint16_t *) (header + 4)) = ntohs(errorCode);

    if ((WXBuffer_Append(&(conn->response), header, 6, TRUE) == NULL) ||
            (WXBuffer_Printf(&(conn->response), errorFormat,
                             title, buffer.buffer) == NULL)) {
        WXLog_Error("Unable to allocate error response buffer");
        NGXMGR_UpdateEvents(conn, WXEVENT_CLOSE);
        NGXMGR_DestroyConnection(conn);
        WXBuffer_Destroy(&buffer);
        return;
    }
    WXBuffer_Destroy(&buffer);

#ifdef NGXMGR_TRACE_MSG
    WXLog_Binary(WXLOG_DEBUG, conn->response.buffer, 0, conn->response.length);
#endif

    /* Attempt a write, resetting flags as required */
    rc = WXSocket_Send(conn->connectionHandle, conn->response.buffer,
                       conn->response.length, 0);
    if (rc < 0) {
        WXLog_Error("Write error for error response: %s",
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

/**
 * Process an incoming event from the main event loop.
 *
 * @param conn Connection instance that has the event.
 * @param events Bitmask of events that have been received.
 */
void NGXMGR_ProcessEvent(NGXModuleConnection *conn, uint32_t events) {
    char *ptr, *action = NULL, *sessionId, *sourceIpAddr, *request;
    int l, len, rc, sessionIsValid = FALSE;
    NGXMGR_Profile *profile;
    char timestamp[128];
    uint8_t command;

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
        command = *(conn->requestHeader);

#ifdef NGXMGR_TRACE_MSG
        WXLog_Binary(WXLOG_DEBUG, conn->request.buffer, 0,
                     conn->request.length);
#endif
        ptr = conn->request.buffer;
        len = conn->request.length;

        /* Right up front, parse, log and validate the session! */
        if (command == NGXMGR_SESSION_ACTION) {
            l = ntohs(*((uint16_t *) ptr));
            ptr += 2; len -= 2;
            if ((l > len) || (*(ptr + l) != '\0')) {
                WXLog_Error("Protocol error, invalid session action");
                NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                                "Internal Error: invalid message protocol...");
                return;
            }
            action = ptr;
            l++; ptr += l; len -= l;
        }

        l = ntohs(*((uint16_t *) ptr));
        ptr += 2; len -= 2;
        if ((l > len) || (*(ptr + l) != '\0')) {
            WXLog_Error("Protocol error, invalid profile identifier");
            NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                                "Internal Error: invalid message protocol...");
            return;
        }
        profile = (NGXMGR_Profile *) WXHash_GetEntry(&(GlobalConfig.profiles),
                                                     ptr, WXHash_StrCaseHashFn,
                                                     WXHash_StrCaseEqualsFn);
        if (profile == NULL) {
            WXLog_Error("Session request for unknown profile '%s'", ptr);
            NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                                "Internal Error: invalid manager config...");
            return;
        }
        l++; ptr += l; len -= l;

        l = ntohs(*((uint16_t *) ptr));
        ptr += 2; len -= 2;
        if ((l > len) || (*(ptr + l) != '\0')) {
            WXLog_Error("Protocol error, invalid session identifier");
            NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                                "Internal Error: invalid message protocol...");
            return;
        }
        sessionId = ptr;
        l++; ptr += l; len -= l;

        l = ntohs(*((uint16_t *) ptr));
        ptr += 2; len -= 2;
        if ((l > len) || (*(ptr + l) != '\0')) {
            WXLog_Error("Protocol error, invalid source IP address");
            NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                                "Internal Error: invalid message protocol...");
            return;
        }
        sourceIpAddr = ptr;
        l++; ptr += l; len -= l;

        l = ntohs(*((uint16_t *) ptr));
        ptr += 2; len -= 2;
        if ((l > len) || (*(ptr + l) != '\0')) {
            WXLog_Error("Protocol error, invalid request information");
            NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                                "Internal Error: invalid message protocol...");
            return;
        }
        request = ptr;
        l++; ptr += l; len -= l;

        /* Any trailing elements are ACTION details, ignored for others */

        /* Validate session up front, so we can log determined state */
        /* TODO - use profile standards (fixed IP, for example) */
        /* TODO - actually do it against the internal tables */

        /* Generate session log entry if enabled */
        if (GlobalConfig.sessionLogFile != NULL) {
            WXLog_GetFormattedTimestamp(timestamp);

            (void) fprintf(GlobalConfig.sessionLogFile,
                           "%s %s%s%s[%s:%s->%s] %s\n",
                           timestamp, profile->name,
                           ((action != NULL) ? ":" : ""), action,
                           sessionId, sourceIpAddr,
                           ((sessionIsValid) ? "Y" : "N"), request);
            (void) fflush(GlobalConfig.sessionLogFile);
        }

        /* Certain conditions are immediately resolvable */
        if ((sessionIsValid) && (command != NGXMGR_SESSION_ACTION)) {
            /* All verify requests just continue if session is validated */
            NGXMGR_IssueResponse(conn, NGXMGR_SESSION_CONTINUE, "", 0);
        } else if (command == NGXMGR_VALIDATE_SESSION) {
            /* For validate, only response is invalid if not valid */
            NGXMGR_IssueResponse(conn, NGXMGR_SESSION_INVALID, "", 0);
           
        } else {
            /* Let the profile handle the remaining request actions */
            if (command == NGXMGR_VERIFY_SESSION) {
                (profile->processVerify)(profile, conn, request);
            } else {
                (profile->processAction)(profile, conn, request, action,
                                         sessionId, ptr, len);
            }
        }
    }
}
