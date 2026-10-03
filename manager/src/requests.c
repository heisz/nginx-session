/**
 * Methods for handling the various requests to the session manager.
 *
 * Copyright (C) 2018-2026 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <arpa/inet.h>
#include "manager.h"
#include "socket.h"
#include "log.h"
#include "mem.h"

/* Define this to trace messaging */
// #define NGXMGR_TRACE_MSG 1

/* Forward declaration of the per-connection fiber handler */
static void connectionHandler(void *arg);

/**
 * Allocate a new module connection instance and spawn the fiber that
 * processes the associated request(s).
 *
 * @param connHandle The incoming connection handle.
 * @param origin IP address for the connection as obtained from the accept().
 */
void NGXMGR_AllocateConnection(WXSocket connHandle, const char *origin) {
    NGXModuleConnection *conn;

    /* Fiber requires a non-blocking socket instance */
    if (WXSocket_SetNonBlockingState(connHandle, TRUE) != WXNRC_OK) {
        WXLog_Error("Unable to non-block connection from %s: %s", origin,
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        WXSocket_Close(connHandle);
        return;
    }

    /* Setup connection instance */
    conn = (NGXModuleConnection *) WXMalloc(sizeof(NGXModuleConnection));
    if (conn == NULL) {
        WXLog_Error("Memory failure allocating module connection instance");
        WXSocket_Close(connHandle);
        return;
    }
    conn->connectionHandle = connHandle;
    conn->requestLength = 0;
    conn->closeRequested = FALSE;
    (void) WXBuffer_Init(&(conn->request), 0);
    (void) WXBuffer_Init(&(conn->response), 0);

    /* Spawn the fiber to process, handler owns the connection from here */
    if (GMPS_Start(connectionHandler, conn) == NULL) {
        WXLog_Error("Failed to start fiber for module connection");
        NGXMGR_DestroyConnection(conn);
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
        /* Unregister the socket from the scheduler poll descriptor set */
        (void) GMPS_SocketUnregister(conn->connectionHandle);
        WXSocket_Close(conn->connectionHandle);
    }
    WXFree(conn);
}

/**
 * Common method to setup/issue a response for the pending request on the
 * provided connection.  Note that this only builds the response, actual
 * write occurs from the connection fiber (safe to call under lock).
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
        conn->closeRequested = TRUE;
        return;
    }
#ifdef NGXMGR_TRACE_MSG
    WXLog_Binary(WXLOG_DEBUG, conn->response.buffer, conn->response.offset,
                 conn->response.length - conn->response.offset);
#endif
}

static char *errorFormat =
                "<html><head><title>%s</title></head><body>%s</body></html>";

void NGXMGR_IssueErrorResponse(NGXModuleConnection *conn, uint16_t errorCode,
                               char *title, char *format, ...) {
    uint8_t header[6], msgBuff[1024];
    WXBuffer buffer;
    va_list ap;
    int len;

#ifdef NGXMGR_TRACE_MSG
    WXLog_Debug("Outgoing error: %d: %s", errorCode, title);
#endif

    /* Format the message content */
    WXBuffer_InitLocal(&buffer, msgBuff, sizeof(msgBuff));
    va_start(ap, format);
    if (WXBuffer_VPrintf(&buffer, format, ap) == NULL) {
        WXLog_Error("Unable to allocate error message content");
        conn->closeRequested = TRUE;
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
        conn->closeRequested = TRUE;
        WXBuffer_Destroy(&buffer);
        return;
    }
    WXBuffer_Destroy(&buffer);

#ifdef NGXMGR_TRACE_MSG
    WXLog_Binary(WXLOG_DEBUG, conn->response.buffer, conn->response.offset,
                 conn->response.length - conn->response.offset);
#endif
}

/* Common method to walk the 2-byte length, null-terminated request strings */
static char *readReqEntry(char **ptr, int *len) {
    char *retval;
    int slen;

    if (*len < 3) return NULL;
    slen = ntohs(*((uint16_t *) *ptr));
    if ((slen > *len - 3) || (*(*ptr + 2 + slen) != '\0')) return NULL;

    retval = *ptr + 2;
    *ptr += slen + 3;
    *len -= slen + 3;
    return retval;
}

/**
 * Process a received request from the nginx module, responses are queued
 * on the connection using one of the above methods.
 *
 * @param conn Connection instance that has the request.
 */
static void processRequest(NGXModuleConnection *conn) {
    char *ptr, *action = NULL, *sessionId, *sourceIpAddr, *request, *prfName;
    int len, sessionIsValid = FALSE;
    uint8_t command, attrBuff[1024];
    NGXMGR_Profile *profile;
    WXBuffer sessionAttrs;

    /* Oh, so much tidier with the shceduler handling the event model */
    command = *(conn->requestHeader);

#ifdef NGXMGR_TRACE_MSG
    WXLog_Binary(WXLOG_DEBUG, conn->request.buffer, 0,
                 conn->request.length);
#endif
    ptr = (char *) conn->request.buffer;
    len = conn->request.length;

    /* Only the three defined commands are acceptable */
    if ((command != NGXMGR_VALIDATE_SESSION) &&
            (command != NGXMGR_VERIFY_SESSION) &&
            (command != NGXMGR_SESSION_ACTION)) {
        WXLog_Error("Protocol error, unrecognized command %d", (int) command);
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                            "Internal Error: invalid message protocol...");
        return;
    }

    /* Right up front, parse, log and validate the session! */
    if (command == NGXMGR_SESSION_ACTION) {
        if ((action = readReqEntry(&ptr, &len)) == NULL) {
            WXLog_Error("Protocol error, invalid session action");
            NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                                "Internal Error: invalid message protocol...");
            return;
        }
    }

    /* Extract and verify/retrieve the authentication profile */
    if ((prfName = readReqEntry(&ptr, &len)) == NULL) {
        WXLog_Error("Protocol error, invalid profile identifier");
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                            "Internal Error: invalid message protocol...");
        return;
    }
    profile = NGXMGR_GetProfile(prfName);
    if (profile == NULL) {
        WXLog_Error("Session request for unknown profile '%s'", prfName);
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                            "Internal Error: invalid manager config...");
        return;
    }

    /* Remaining standard/common elements - session, origin IP and details */
    if ((sessionId = readReqEntry(&ptr, &len)) == NULL) {
        WXLog_Error("Protocol error, invalid session identifier");
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                            "Internal Error: invalid message protocol...");
        return;
    }

    if ((sourceIpAddr = readReqEntry(&ptr, &len)) == NULL) {
        WXLog_Error("Protocol error, invalid source IP address");
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                            "Internal Error: invalid message protocol...");
        return;
    }

    if ((request = readReqEntry(&ptr, &len)) == NULL) {
        WXLog_Error("Protocol error, invalid request information");
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                            "Internal Error: invalid message protocol...");
        return;
    }

    /* Any trailing elements are ACTION details, ignored for others */

    /* Validate session up front, so we can log determined state */
    WXBuffer_InitLocal(&sessionAttrs, attrBuff, sizeof(attrBuff));
    sessionIsValid = NGXMGR_ValidateSession(sessionId, sourceIpAddr,
                                            profile->sessionIPLocked,
                                            &sessionAttrs);

    /* Generate session log entry if enabled */
    if (GlobalData.sessionLogFile != NULL) {
        NGXMGR_SessionLog("%s%s%s[%s:%s->%s] %s", profile->name,
                          ((action != NULL) ? ":" : ""),
                          ((action != NULL) ? action : ""),
                          sessionId, sourceIpAddr,
                          ((sessionIsValid) ? "Y" : "N"), request);
    }

    /* Certain conditions are immediately resolvable */
    if ((sessionIsValid) && (command != NGXMGR_SESSION_ACTION)) {
        /* All verify requests just continue if session is validated */
        NGXMGR_IssueResponse(conn, NGXMGR_SESSION_CONTINUE,
                             sessionAttrs.buffer, sessionAttrs.length);
    } else if (command == NGXMGR_VALIDATE_SESSION) {
        /* For validate, only response is invalid if not valid */
        NGXMGR_IssueResponse(conn, NGXMGR_SESSION_INVALID, (uint8_t *) "", 0);
    } else {
        /* Let the profile handle the remaining request actions */
        if (command == NGXMGR_VERIFY_SESSION) {
            (profile->processVerify)(profile, conn, sourceIpAddr, request);
        } else {
            (profile->processAction)(profile, conn, sourceIpAddr, request,
                                     action, sessionId, ptr, len);
        }
    }
    WXBuffer_Destroy(&sessionAttrs);
}

/* Old trick of multi-mode-length for header/content is trivial in fiber */
static int recvFully(NGXModuleConnection *conn, uint8_t *buff, int len,
                     int isHeader) {
    int rc, offset = 0;

    /* Just read until desired length retrieved */
    while (offset < len) {
        /* Read remainder at offset */
        rc = WXSocket_Recv(conn->connectionHandle, buff + offset,
                           len - offset, 0);
        if (rc > 0) {
            offset += rc;
            continue;
        }

        /* Nothing read (pending), yield on the connection for more */
        if (rc == 0) {
            if (GMPS_YieldSocket(conn->connectionHandle, GMPS_EVT_IN) == 0) {
                WXLog_Error("Error waiting on module connection: %s",
                            WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
                return FALSE;
            }
            continue;
        }

        /* Handle error conditions (detailed logging) */
        if (rc == WXNRC_DISCONNECT) {
            if ((isHeader) && (offset == 0)) {
                WXLog_Info("Disconnect from nginx session module");
            } else if (isHeader) {
                WXLog_Error("Truncated header from session module");
            } else {
                WXLog_Error("Truncated request body from session module");
            }
        } else {
            WXLog_Error("Read error in request %s: %s",
                        ((isHeader) ? "header" : "body"),
                        WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        }
        return FALSE;
    }

    return TRUE;
}

/* Fiber counterpart to loop write response with appropriate yields */
static int sendFully(NGXModuleConnection *conn) {
    WXBuffer *rsp = &(conn->response);
    int rc;

    while (rsp->offset < rsp->length) {
        /* Write from buffer offset */
        rc = WXSocket_Send(conn->connectionHandle, rsp->buffer + rsp->offset,
                           rsp->length - rsp->offset, 0);
        if (rc > 0) {
            rsp->offset += rc;
            continue;
        }

        /* Nothing written (clog), yield on the connection for space */
        if (rc == 0) {
            if (GMPS_YieldSocket(conn->connectionHandle, GMPS_EVT_OUT) == 0) {
                WXLog_Error("Error waiting on module connection: %s",
                            WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
                return FALSE;
            }
            continue;
        }

        /* Write failure is just a plain-old error */
        WXLog_Error("Write error for response: %s",
                    WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        return FALSE;
    }

    WXBuffer_Empty(rsp);
    return TRUE;
}

/**
 * Fiber handler to process requests/write responses for the provided
 * connection instance.  Protocol has no multiplexing, just read request,
 * process and send response until closed.
 *
 * @param arg The associated incoming connection instance.
 */
static void connectionHandler(void *arg) {
    NGXModuleConnection *conn = (NGXModuleConnection *) arg;

    /* Repeat until closed */
    while (TRUE) {
        /* Read request header, disconnect here is just regular closure */
        if (!recvFully(conn, conn->requestHeader, 4, TRUE)) break;

        /* Process header, command is left as highest-order byte */
        conn->requestLength =
                   ntohl(*((int32_t *) conn->requestHeader)) & 0x00FFFFFF;

#ifdef NGXMGR_TRACE_MSG
        WXLog_Debug("Incoming request %d, length %d",
                    *(conn->requestHeader), conn->requestLength);
#endif

        /* Check for invalid length */
        if ((conn->requestLength <= 0) ||
                (((size_t) conn->requestLength) > GlobalData.maxRequestSize)) {
            WXLog_Error("Invalid request length %d from session module",
                        conn->requestLength);
            break;
        }

        /* Allocate and read the body of the request */
        if (WXBuffer_EnsureCapacity(&(conn->request), conn->requestLength,
                                    TRUE) == NULL) {
            WXLog_Error("Unable to allocate request buffer (len %d)",
                        conn->requestLength);
            break;
        }
        conn->request.length = conn->request.offset = 0;
        if (!recvFully(conn, conn->request.buffer,
                       conn->requestLength, FALSE)) break;
        conn->request.length = conn->requestLength;
        conn->requestLength = 0;

        /* Process request content, stages outbound response */
        processRequest(conn);

        /* Break loop on failure, otherwise send response (ditto) */
        if (conn->closeRequested) break;
        if (!sendFully(conn)) break;
    }

    NGXMGR_DestroyConnection(conn);
}
