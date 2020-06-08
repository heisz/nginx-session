/*
 * Custom NGINX upstream implementation for binary manager communication.
 *
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_session_module.h"
#include "messages.h"

/**
 * Callback method to handle the initial outbound request to the session
 * manager instance.
 *
 * @param req The associated HTTP request instance (must have an underlying
 *            manager request context bound to it).
 * @return Suitable NGX_* response code for the main engine.
 */
static ngx_int_t ngx_http_session_create_request(ngx_http_request_t *req) {
    ngx_http_session_request_ctx_t *ctx;
    ngx_chain_t *chn;
    ngx_buf_t *buff;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: creating upstream request");

    /* Need the original request context for the send data */
    ctx = ngx_http_get_module_ctx(req, ngx_http_session_module);

    /* Create a buffer instance and populate it with the original request */
    buff = ngx_create_temp_buf(req->pool, ctx->request_length);
    if (buff == NULL) return NGX_ERROR;
    buff->last = ngx_copy(buff->last, ctx->request_content,
                          ctx->request_length);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: chaining outbound buffer: %d bytes",
                   (int) ctx->request_length);

    /* Build a buffer chain with the allocated buffer as content */
    chn = ngx_alloc_chain_link(req->pool);
    if (chn == NULL) return NGX_ERROR;
    chn->buf = buff;
    chn->next = NULL;

    /* And attach it to the upstream pending requests */
    req->upstream->request_bufs = chn;

    return NGX_OK;
}

/**
 * Handle state re-initialization on a connection failure with the upstream
 * instance.  The session manager integration maintains no request state
 * outside of the full request setup, so this method does nothing.
 *
 * @param req The associated HTTP request instance (must have an underlying
 *            manager request context bound to it).
 * @return Suitable NGX_* response code for the main engine.
 */
static ngx_int_t ngx_http_session_reinit_request(ngx_http_request_t *req) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: reinitialize request");

    return NGX_OK;
}

/* Note, this needs to align exactly with the enumeration */
static char *ngx_https_session_rcstr[] = {
    "Response_Pending", "Session_Invalid", "Session_Continue",
    "External_Redirect", "Content_Response" ,"Error_Response"
};

/**
 * Parse the response information from the manager, translating it into
 * an upstream response for handing off/back to the module instance.
 *
 * @param req The associated HTTP request instance (must have an underlying
 *            manager request context bound to it).
 * @return Suitable NGX_* response code for the main engine.
 */
static ngx_int_t ngx_http_session_process_header(ngx_http_request_t *req) {
    ngx_http_upstream_t *upstr = req->upstream;
    ngx_http_session_request_ctx_t *ctx =
                        ngx_http_get_module_ctx(req, ngx_http_session_module);
    uint32_t respLen, buffLen;
    uint16_t typeLen;
    u_char code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: process header");

    /* Read again until entire binary header can be processed */
    buffLen = upstr->buffer.last - upstr->buffer.pos;
    if (buffLen < 4) return NGX_AGAIN;
    respLen = ntohl(*((uint32_t *) upstr->buffer.pos)) & 0x00FFFFFF;
    code = *(upstr->buffer.pos);
    upstr->length = respLen + 4;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: manager response %s: %d bytes",
                   ngx_https_session_rcstr[code], (int) respLen);

    /* Five types of responses, the key one being the continue redirect! */
    if (code == NGXMGR_SESSION_INVALID) {
        /* Full response is required (but should be here, being empty) */

        /* See note below, also would have liked to return DECLINED so that
         * the upstream could fall through in this case, no such luck.  Either
         * switch to the target or issue an unauthorized error condition.
         */
        if (ctx->slcf->invalid_redirect_target.data == NULL) {
            /* TODO - should we inject page content for display? */
            upstr->headers_in.content_length_n = 0;
            upstr->headers_in.status_n = NGX_HTTP_UNAUTHORIZED;
            upstr->buffer.pos += 4 + respLen;
            upstr->keepalive = 1;
            return NGX_OK;
        } else {
            upstr->headers_in.x_accel_redirect =
                               ngx_list_push(&(upstr->headers_in.headers));
            if (upstr->headers_in.x_accel_redirect == NULL) return NGX_ERROR;
            upstr->headers_in.x_accel_redirect->hash = 1;
            ngx_str_set(&(upstr->headers_in.x_accel_redirect->key),
                        "X-Accel-Redirect");
            upstr->headers_in.x_accel_redirect->value =
                                    ctx->slcf->invalid_redirect_target;
            upstr->headers_in.content_length_n = 0;
            upstr->headers_in.status_n = NGX_HTTP_OK;
            upstr->buffer.pos += 4 + respLen;
            upstr->keepalive = 1;
        }

        return NGX_OK;
    }

    if (code == NGXMGR_SESSION_CONTINUE) {
        /* Full response is required (but should be here, being empty) */

        /* Note: there was a lot of experimentation with redirect, but it kept
         *       exploding because we are in upstream, not the primary handler.
         *       Eventually, realized that the accel-redirect mechanism was
         *       intended for things like php/lua, so hijacked that instead...
         */
        upstr->headers_in.x_accel_redirect =
                               ngx_list_push(&(upstr->headers_in.headers));
        if (upstr->headers_in.x_accel_redirect == NULL) return NGX_ERROR;
        upstr->headers_in.x_accel_redirect->hash = 1;
        ngx_str_set(&(upstr->headers_in.x_accel_redirect->key),
                    "X-Accel-Redirect");
        upstr->headers_in.x_accel_redirect->value =
                                ctx->slcf->valid_redirect_target;
        upstr->headers_in.content_length_n = 0;
        upstr->headers_in.status_n = NGX_HTTP_OK;
        upstr->buffer.pos += 4 + respLen;
        upstr->keepalive = 1;

        return NGX_OK;
    }

    if (code == NGXMGR_EXTERNAL_REDIRECT) {
        /* Full response is required for redirect URL */
        if (buffLen < respLen) return NGX_AGAIN;

        /* Push it to the location header */
        req->headers_out.location = ngx_list_push(&(req->headers_out.headers));
        if (req->headers_out.location == NULL) return NGX_ERROR;
        req->headers_out.location->hash = 1;
        ngx_str_set(&(req->headers_out.location->key), "Location");
        req->headers_out.location->value.len = respLen;
        req->headers_out.location->value.data = ngx_palloc(req->pool, respLen);
        if (req->headers_out.location->value.data == NULL) return NGX_ERROR;
        ngx_memcpy(req->headers_out.location->value.data,
                   upstr->buffer.pos + 4, respLen);

        /* And redirect */
        upstr->length = upstr->headers_in.content_length_n = 0;
        upstr->headers_in.status_n = NGX_HTTP_MOVED_TEMPORARILY;
        upstr->state->status = NGX_HTTP_MOVED_TEMPORARILY;
        upstr->buffer.pos += 4 + respLen;
        upstr->keepalive = 1;
        req->header_only = 1;

        return NGX_OK;
    }

    /* Errors and content only differ in their status code and content type */
    if (code == NGXMGR_CONTENT_RESPONSE) {
        if (buffLen < 6) return NGX_AGAIN;
        typeLen = ntohs(*((uint16_t *) (upstr->buffer.pos + 4)));
        if (buffLen < (uint32_t) (typeLen + 6)) return NGX_AGAIN;

        /* Outbound content type comes from response */
        req->headers_out.content_type.len = typeLen;
        req->headers_out.content_type.data = ngx_palloc(req->pool, typeLen);
        if (req->headers_out.content_type.data == NULL) return NGX_ERROR;
        ngx_memcpy(req->headers_out.content_type.data,
                   upstr->buffer.pos + 6, typeLen);
        req->headers_out.content_type_lowcase = NULL;

        /* Remainder is streamed from incoming response */
        upstr->length = upstr->headers_in.content_length_n = respLen - 2 - typeLen;
        upstr->headers_in.status_n = upstr->state->status = NGX_HTTP_OK;
        upstr->buffer.pos += 6 + typeLen;
        upstr->keepalive = 1;

        return NGX_OK;
    }

    if (code == NGXMGR_ERROR_RESPONSE) {
        if (buffLen < 6) return NGX_AGAIN;

        /* Error page content is always HTML */
        req->headers_out.content_type_len = sizeof("text/html") - 1;
        ngx_str_set(&(req->headers_out.content_type), "text/html");
        req->headers_out.content_type_lowcase = NULL;

        /* Remainder is streamed from incoming response */
        upstr->headers_in.content_length_n = respLen - 2;
        upstr->headers_in.status_n = upstr->state->status =
                               ntohs(*((uint16_t *) (upstr->buffer.pos + 4)));
        upstr->length = upstr->headers_in.content_length_n -
                        (buffLen - 6);
fprintf(stderr, "HERE %d %d\n", (int) upstr->headers_in.content_length_n,
                (int) upstr->length);
        upstr->buffer.pos += 6;
        upstr->keepalive = 1;

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                  "*** session manager: invalid manager response");
    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}

/**
 * Handle an abort of the underlying manager request.  Nothing to do here,
 * standard request cleanup will finish it from the module side.
 *
 * @param req The associated HTTP request instance (must have an underlying
 *            manager request context bound to it).
 */
static void ngx_http_session_abort_request(ngx_http_request_t *req) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: abort request");
}

/**
 * Finalize the original request.  Since all of the handling of the response
 * was processed in the header callback, this is also empty.
 *
 * @param req The associated HTTP request instance (must have an underlying
 *            manager request context bound to it).
 * @param rc The final return status code for the request.
 */
static void ngx_http_session_finalize_request(ngx_http_request_t *req,
                                              ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: finalize request %d", rc);
}

/*
 * Note: at one point (experimentation) I had defined filter chains in here
 *       to get response output to appear.  But it turns out that they aren't
 *       needed (at present) since the response is sent verbatim.  All of the
 *       setup is accomplished in the header processing method and the
 *       nginx engine takes it from there...
 */

/**
 * Create a new upstream instance for issuing an underlying request to the
 * session manager.
 *
 * @param smcf The configuration object for the session location (for upstream
 *             data/configuration access).
 * @param req The associated HTTP request instance (must have an underlying
 *            manager request context bound to it).
 * @return Suitable NGX_* response code for the main engine.
 */
ngx_int_t ngx_http_session_create_upstream(ngx_http_session_loc_conf_t *smcf,
                                           ngx_http_request_t *req,
                                           ngx_http_session_request_ctx_t *ctx){
    ngx_http_upstream_t *upstr;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                  "*** session manager: creating upstream request instance");

    /* Create the upstream data instance */
    if (ngx_http_upstream_create(req) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    upstr = req->upstream;

    /* Pull the associated module/configuration details */
    upstr->output.tag = (ngx_buf_tag_t) &ngx_http_session_module;
    upstr->conf = &smcf->manager;

    /* Define all of the local message processing methods */
    upstr->create_request = ngx_http_session_create_request;
    upstr->reinit_request = ngx_http_session_reinit_request;
    upstr->process_header = ngx_http_session_process_header;
    upstr->abort_request = ngx_http_session_abort_request;
    upstr->finalize_request = ngx_http_session_finalize_request;

    /* If needed (see above), filtering methods could be defined here */

    /* Attach to the underlying request instance */
    req->upstream = upstr;
    req->main->count++;

    /* Bombs away! */
    ngx_http_upstream_init(req);

    return NGX_OK;
}
