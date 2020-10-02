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
    ngx_chain_t *chn, *lnk;
    ngx_int_t blen = 0;
    ngx_buf_t *buff;
    uint8_t cmd;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: creating upstream request");

    /* Verify body content availability (memory) and compute net length */
    /* Not clear if content_length_n is updated by NGINX, follow examples... */
    if (req->request_body->temp_file != NULL) {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                      "Session POST actions must fit into memory buffer, "
                      "adjust client_body_buffer_size > [%d bytes]",
                      (int) req->headers_in.content_length_n);
        return NGX_HTTP_INSUFFICIENT_STORAGE;
    }
    lnk = req->request_body->bufs;
    while (lnk != NULL) {
        blen += ngx_buf_size(lnk->buf);
        lnk = lnk->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: request data %d bytes", (int) blen);

    /* Need the original request context for the send data */
    ctx = ngx_http_get_module_ctx(req, ngx_http_session_module);
    cmd = *(ctx->request_content);

    /* Create a buffer instance and populate it with the original request */
    buff = ngx_create_temp_buf(req->pool, ctx->request_length + blen);
    if (buff == NULL) return NGX_ERROR;
    buff->last = ngx_copy(buff->last, ctx->request_content,
                          ctx->request_length);

    /* Append body content as provided, rewriting length */
    if (blen != 0) {
        lnk = req->request_body->bufs;
        while (lnk != NULL) {
            buff->last = ngx_copy(buff->last, lnk->buf->pos,
                                  ngx_buf_size(lnk->buf));
            lnk = lnk->next;
        }

        *((uint32_t *) buff->pos) = htonl(ngx_buf_size(buff) - 4);
        *(buff->pos) = cmd;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: chaining outbound buffer: %d bytes",
                   (int) ngx_buf_size(buff));

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
    "response_pending", "session_invalid", "session_continue",
    "session_establish", "external_redirect", "content_response",
    "error_response", "unknown"
};

/* Validator for incoming string sequences (URL and variables) */
static ngx_int_t ngx_http_session_validate_strlist(u_char *ptr, uint32_t len,
                                                   uint16_t *first) {
    ngx_int_t cnt = 0;
    uint16_t l;

    while (len > 3) {
        l = ntohs(*((uint16_t *) ptr));
        if (l > (len - 2)) return -1;
        ptr += l + 2;
        if (*(ptr++) != '\0') return -1;
        len -= l + 3;
        if (((cnt++) == 0) && (first != NULL)) *first = l;
    }
    if (len != 0) return -1;
    return cnt;
}

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
    uint32_t resp_len, buff_len;
    uint16_t type_len, url_len;
    ngx_table_elt_t *sess_hdr;
    ngx_int_t cnt;
    u_char code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: process header");

    /* Read again until entire binary header can be processed */
    buff_len = upstr->buffer.last - upstr->buffer.pos;
    if (buff_len < 4) return NGX_AGAIN;
    resp_len = ntohl(*((uint32_t *) upstr->buffer.pos)) & 0x00FFFFFF;
    code = *(upstr->buffer.pos);
    upstr->length = resp_len + 4;

    if (code >= NGXMGR_ERROR_UKNOWN) code = NGXMGR_ERROR_UKNOWN;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: manager response %s: %d bytes",
                   ngx_https_session_rcstr[code], (int) resp_len);

    /* Five types of responses, the key one being the continue redirect! */
    if (code == NGXMGR_SESSION_INVALID) {
        /* Full response is required (but should be here, being empty) */

        /*
         * See note below, also would have liked to return DECLINED so that
         * the upstream could fall through in this case, no such luck.  Either
         * switch to the target or issue an unauthorized error condition.
         */
        if (ctx->slcf->invalid_redirect_target.data == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                           "*** session manager: invalid sessn, unauthorized");

            /* TODO - should we inject page content for display? */
            upstr->headers_in.content_length_n = 0;
            upstr->headers_in.status_n = NGX_HTTP_UNAUTHORIZED;
            upstr->buffer.pos += 4 + resp_len;
            upstr->keepalive = 1;
            return NGX_OK;
        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                           "*** session manager: invalid sessn, redirect %*s",
                           (int) ctx->slcf->invalid_redirect_target.len,
                           ctx->slcf->invalid_redirect_target.data);

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
            upstr->buffer.pos += 4 + resp_len;
            upstr->keepalive = 1;
        }

        return NGX_OK;
    }

    if (code == NGXMGR_SESSION_CONTINUE) {
        /* Full response is required for variable handling */
        if (buff_len < resp_len) return NGX_AGAIN;

        /* Verify variable set, assign to context */
        cnt = ngx_http_session_validate_strlist(upstr->buffer.pos + 4,
                                                resp_len, NULL);
        if ((cnt <= 0) || ((cnt & 0x01) != 0)) {
            ngx_log_error(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                          "*** session manager: invalid manager varset");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /*
         * Note: there was a lot of experimentation with redirect, but it kept
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
        upstr->buffer.pos += 4 + resp_len;
        upstr->keepalive = 1;

        return NGX_OK;
    }

    if (code == NGXMGR_SESSION_ESTABLISH) {
        /* Full response is required for redirect and variable setting */
        if (buff_len < resp_len) return NGX_AGAIN;

        /* Verify variable set, assign to context */
        cnt = ngx_http_session_validate_strlist(upstr->buffer.pos + 4,
                                                resp_len, &url_len);
        if ((cnt <= 0) || ((cnt & 0x01) != 1)) {
            ngx_log_error(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                          "*** session manager: invalid manager sess/varset");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* Set up the redirect header (TODO - handle @ internal redirect?) */
        /* Or handle empty local configuration? */
        req->headers_out.location = ngx_list_push(&(req->headers_out.headers));
        if (req->headers_out.location == NULL) return NGX_ERROR;
        req->headers_out.location->hash = 1;
        ngx_str_set(&(req->headers_out.location->key), "Location");
        req->headers_out.location->value.len = url_len;
        req->headers_out.location->value.data = ngx_palloc(req->pool, url_len);
        if (req->headers_out.location->value.data == NULL) return NGX_ERROR;
        ngx_memcpy(req->headers_out.location->value.data,
                   upstr->buffer.pos + 6, url_len);

        /* Define the context attribute set */
        ctx->attributes_length = resp_len - url_len - 7;
        ctx->attributes = ngx_palloc(req->pool, ctx->attributes_length);
        if (ctx->attributes == NULL) return NGX_ERROR;
        (void) memcpy(ctx->attributes, upstr->buffer.pos + url_len + 7,
                      ctx->attributes_length);

        /* Push the session cookie if defined (first attribute named sid) */
        if (ctx->slcf->cookie_name.len != 0) {
            sess_hdr = ngx_list_push(&(req->headers_out.headers));
            if (sess_hdr == NULL) return NGX_ERROR;
            sess_hdr->hash = 1;
            ngx_str_set(&(sess_hdr->key), "Set-Cookie");
            sess_hdr->value.len =
                   ntohs(*((uint16_t *) (ctx->attributes + 6)));
            sess_hdr->value.data = ngx_palloc(req->pool, sess_hdr->value.len);
            if (sess_hdr->value.data == NULL) return NGX_ERROR;
            ngx_memcpy(sess_hdr->value.data,
                       ctx->attributes + 8, sess_hdr->value.len);
        }

        /* Entire response is just a header set of redirect */
        upstr->headers_in.content_length_n = 0;
        upstr->headers_in.status_n = NGX_HTTP_MOVED_TEMPORARILY;
        upstr->state->status = NGX_HTTP_MOVED_TEMPORARILY;
        upstr->buffer.pos += 4 + resp_len;
        req->header_only = 1;
        upstr->keepalive = 1;

        return NGX_OK;
    }

    if (code == NGXMGR_EXTERNAL_REDIRECT) {
        /* Full response is required for redirect URL */
        if (buff_len < resp_len) return NGX_AGAIN;

        /* Push it to the location header */
        req->headers_out.location = ngx_list_push(&(req->headers_out.headers));
        if (req->headers_out.location == NULL) return NGX_ERROR;
        req->headers_out.location->hash = 1;
        ngx_str_set(&(req->headers_out.location->key), "Location");
        req->headers_out.location->value.len = resp_len;
        req->headers_out.location->value.data = ngx_palloc(req->pool, resp_len);
        if (req->headers_out.location->value.data == NULL) return NGX_ERROR;
        ngx_memcpy(req->headers_out.location->value.data,
                   upstr->buffer.pos + 4, resp_len);

        /* Entire response is just a header set of redirect */
        upstr->headers_in.content_length_n = 0;
        upstr->headers_in.status_n = NGX_HTTP_MOVED_TEMPORARILY;
        upstr->state->status = NGX_HTTP_MOVED_TEMPORARILY;
        upstr->buffer.pos += 4 + resp_len;
        req->header_only = 1;
        upstr->keepalive = 1;

        return NGX_OK;
    }

    /* Errors and content only differ in their status code and content type */
    if (code == NGXMGR_CONTENT_RESPONSE) {
        if (buff_len < 6) return NGX_AGAIN;
        type_len = ntohs(*((uint16_t *) (upstr->buffer.pos + 4)));
        if (buff_len < (uint32_t) (type_len + 6)) return NGX_AGAIN;

        /* Outbound content type comes from response */
        req->headers_out.content_type.len = type_len;
        req->headers_out.content_type.data = ngx_palloc(req->pool, type_len);
        if (req->headers_out.content_type.data == NULL) return NGX_ERROR;
        ngx_memcpy(req->headers_out.content_type.data,
                   upstr->buffer.pos + 6, type_len);
        req->headers_out.content_type_lowcase = NULL;

        /* Remainder is streamed from incoming response */
        upstr->headers_in.content_length_n = resp_len - 2 - type_len;
        upstr->headers_in.status_n = upstr->state->status = NGX_HTTP_OK;
        upstr->buffer.pos += 6 + type_len;
        upstr->keepalive = 1;

        return NGX_OK;
    }

    if (code == NGXMGR_ERROR_RESPONSE) {
        if (buff_len < 6) return NGX_AGAIN;

        /* Error page content is always HTML */
        req->headers_out.content_type_len = sizeof("text/html") - 1;
        ngx_str_set(&(req->headers_out.content_type), "text/html");
        req->headers_out.content_type_lowcase = NULL;

        /* Remainder is streamed from incoming response */
        upstr->headers_in.content_length_n = resp_len - 2;
        upstr->headers_in.status_n = upstr->state->status =
                               ntohs(*((uint16_t *) (upstr->buffer.pos + 4)));
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

/**
 * Turns out we need filter chains to properly handle the keepalive length
 * processing for the manager engine.
 */
static ngx_int_t ngx_http_session_filter_init(void *data) {
    ngx_http_session_request_ctx_t *ctx =
                      (ngx_http_session_request_ctx_t *) data;
    ngx_http_upstream_t *upstr = ctx->request->upstream;

    /*
     * Long story short.  Setting upstream length in process_header does not
     * work, because core NGINX handler resets length to -1 (read until upstream
     * closes).  So need to have an input filter to set the length, which
     * happens after header processing.
     */
    upstr->length = upstr->headers_in.content_length_n;
    upstr->keepalive = 1;

    return NGX_OK;
}

/* Note: this is essentially ngx_http_upstream_non_buffered_filter (static) */
static ngx_int_t ngx_http_session_filter(void *data, ssize_t bytes) {
    ngx_http_session_request_ctx_t *ctx =
                      (ngx_http_session_request_ctx_t *) data;
    ngx_http_upstream_t *upstr = ctx->request->upstream;
    ngx_chain_t *cl, **ll;
    ngx_buf_t *b;

    /* Allocate a free chain buffer onto the end of the upstream */
    ll = &(upstr->out_bufs); 
    for (cl = upstr->out_bufs; cl != NULL; cl = cl->next) {
        ll = &(cl->next);
    }
    cl = ngx_chain_get_free_buf(ctx->request->pool, &(upstr->free_bufs));
    if (cl == NULL) return NGX_ERROR;
    *ll = cl;

    /* Transfer the byte stream to the output buffer */
    b = &(upstr->buffer);
    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = upstr->output.tag;
    cl->buf->flush = 1;
    cl->buf->memory = 1;

    /* All this to get to this action... */
    upstr->length -= bytes;

    return NGX_OK;
}

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
    ngx_int_t rc;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                  "*** session manager: creating upstream request instance");

    /* Create the upstream data instance */
    if ((rc = ngx_http_upstream_create(req)) != NGX_OK) {
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

    /* Attach a no-op filter to properly set the upstream length */
    upstr->input_filter_init = ngx_http_session_filter_init;
    upstr->input_filter = ngx_http_session_filter;
    upstr->input_filter_ctx = ctx;

    /*
     * Notes from experimentation, if you discard the body, need to increment
     * req->main->count.  But if reading the body, don't do that or you end 
     * up in a loop of unfinished requests...
     */

    /* Collect any incoming POST data and process upstream */
    rc = ngx_http_read_client_request_body(req, ngx_http_upstream_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) return rc;

    return NGX_DONE;
}
