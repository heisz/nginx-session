/**
 * Definition for messaging protocol of the nginx session management module.
 * 
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#ifndef NGXSESS_MESSAGES_H
#define NGXSESS_MESSAGES_H 1

/*
 * The binary protocol between the nginx module and the underlying manager is
 * relatively straightforward.  The header of each message is 4 bytes, the first
 * byte (in send order) is either the outbound command or the manager response
 * code.  The remaining three bytes form the length in network (big-endian)
 * order, where the highest order byte is always zero and replaced with the
 * command/response code.  Does limit the packet size to 16,581,375 bytes,
 * which most likely won't be a problem...
 *
 * The contents are almost entirely made of strings, which are encoded as a
 * two byte length (network order) followed by the character data, without
 * terminator, unless specified otherwise (content).
 *
 * Content for each command/response follows...
 */

typedef enum NGXMGR_Command {
    /*
     * For the primary two commands of the NGINX session module (see below),
     * the following information is included in the outbound packet.
     *
     *   - sessionId - standard string containing externally provided session
     *                 identifier or access token
     *   - sourceAddr - standard string containing IP address of the source
     *                  request, for logging and optional validation
     *   - request - standard string containing amalgamated method/uri details
     *               of the request, for logging
     */

    /*
     * Test the validity of the provided session identifier only, returns
     * either the SESSION_INVALID or SESSION_CONTINUE response based on the
     * validity of the session.  Request content was detailed above.
     */
    NGXMGR_VALIDATE_SESSION = 0x01,

    /*
     * Verify the session, returning either SESSION_CONTINUE if the session
     * is valid or a suitable response to either initiate a login or push
     * an error, based on conditions.  Request content was detailed above.
     */
    NGXMGR_VERIFY_SESSION = 0x02
} NGXMGR_Command;

typedef enum NGXMGR_Response {
    /*
     * Special marker for pending responses (never sent, for internal state
     * management only).
     */
    NGXMGR_RESPONSE_PENDING = 0x00,

    /*
     * VALIDATE_SESSION response when the session is invalid but no action is
     * to be taken by the module.  There is no additional content with this
     * response, all directives are managed by the nginx configuration.
     */
    NGXMGR_SESSION_INVALID = 0x01,

    /*
     * VALIDATE_SESSION response when the session is valid and processing
     * can continue (redirect by the nginx module).  There is no additional
     * content with this response, all directives are managed by the nginx
     * configuration.
     */
    NGXMGR_SESSION_CONTINUE = 0x02,

    /*
     * Response for any request, perform a 302 (temporarily moved) redirect
     * either for OAuth/SSO processing or login redirection.  Content contains
     * the text of the redirect location (not a length-lead string).
     */
    NGXMGR_EXTERNAL_REDIRECT = 0x03,

    /*
     * Common response type for manager streamed content (verbatim).  Returns
     * an HTTP 200 (ok) response code with the provided content.  Response
     * content:
     *     - content type (standard string)
     *     - associated page content, no length as the entire remainder
     *       of the message is the content
     */
    NGXMGR_CONTENT_RESPONSE = 0x04,

    /*
     * Response for any request, issue an error response (mainly intended for
     * internal error conditions).  Response content:
     *     - HTTP response (error) code, uint16 in network byte order
     *     - associated error page content, no length as the entire remainder
     *       of the message is the content
     */
    NGXMGR_ERROR_RESPONSE = 0x05
} NGXMGR_Response;

#endif
