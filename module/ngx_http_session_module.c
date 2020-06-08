/*
 * Primary module engine entry point for the NGINX session management module.
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

/* Forward declaration of the segregated request handlers */
static char *ngx_http_session_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
                                       void *conf);
static char *ngx_http_session_verify(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_session_action(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_session_status(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);

/* For convenience below */
#define NGX_HTTP_GLOBAL_CONF \
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF

/**
 * Definition of the configuration directives for the module.  Did experiment
 * with various settings of standard configuration so that all of the options
 * could be contained within a single block, but the nginx configuration parser
 * gets a little (actually a lot) upset at that model...
 */
static ngx_command_t ngx_http_session_commands[] = {
    /* The following are common upstream/manager settings, available anywhere */
    /* Credit due, these were obtained from the nginx memcached module source */
    { ngx_string("session_socket_keepalive"),
      NGX_HTTP_GLOBAL_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_loc_conf_t, manager.socket_keepalive),
      NULL },

    { ngx_string("session_connect_timeout"),
      NGX_HTTP_GLOBAL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_loc_conf_t, manager.connect_timeout),
      NULL },

    { ngx_string("session_send_timeout"),
      NGX_HTTP_GLOBAL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_loc_conf_t, manager.send_timeout),
      NULL },

    { ngx_string("session_buffer_size"),
      NGX_HTTP_GLOBAL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_loc_conf_t, manager.buffer_size),
      NULL },

    { ngx_string("session_read_timeout"),
      NGX_HTTP_GLOBAL_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_loc_conf_t, manager.read_timeout),
      NULL },

    /* Enablement for session-protected resource access (location only) */
    { ngx_string("session_redirect"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4,
      ngx_http_session_redirect,
      NGX_HTTP_LOC_CONF_OFFSET, 
      0, NULL},

    { ngx_string("session_verify"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE3 | NGX_CONF_TAKE4, 
      ngx_http_session_verify,
      NGX_HTTP_LOC_CONF_OFFSET, 
      0, NULL},

    { ngx_string("session_action"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE3,
      ngx_http_session_action,
      NGX_HTTP_LOC_CONF_OFFSET, 
      0, NULL},

    /* Associated settings for session management elements */
    { ngx_string("session_cookie"),
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      offsetof(ngx_http_session_loc_conf_t, cookie_id),
      0, NULL},

    { ngx_string("session_oauth"),
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET, 
      offsetof(ngx_http_session_loc_conf_t, oauth_enabled),
      NULL},

    { ngx_string("session_property"),
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET, 
      offsetof(ngx_http_session_loc_conf_t, session_property),
      NULL},

    /* Status command for debugging interface */
    { ngx_string("session_status"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_http_session_status,
      NGX_HTTP_LOC_CONF_OFFSET, 
      0, NULL},

    ngx_null_command
};

/**
 * Wow.  For anyone gandering at this code, I spent hours and hours trying to
 * figure out why my requests would core dump when handing off to the upstream
 * instance to process the request.  Turns out that there is key data created
 * in the core upstream instance that needs to be inherited for it to work.
 * So one requires both the creation/allocate method for the configuration as
 * well as the merge method (following).  Sounds obvious once you type it but
 * that wasn't the case for a about a week or so...
 *
 * @param cf The main configuration object, to allocate the location config
 *           instance against.
 * @return The allocated and initialized location configuration object.
 */
static void *ngx_http_session_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_session_loc_conf_t  *conf;

    /* Allocate the object */
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_session_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* This is the set of default upstream options from the memcached module */
    conf->manager.local = NGX_CONF_UNSET_PTR;
    conf->manager.socket_keepalive = NGX_CONF_UNSET;
    conf->manager.next_upstream = NGX_HTTP_UPSTREAM_FT_OFF;
    conf->manager.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->manager.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->manager.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->manager.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->manager.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->manager.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->manager.cyclic_temp_file = 0;
    conf->manager.buffering = 0;
    conf->manager.ignore_client_abort = 0;
    conf->manager.send_lowat = 0;
    conf->manager.bufs.num = 0;
    conf->manager.busy_buffers_size = 0;
    conf->manager.max_temp_file_size = 0;
    conf->manager.temp_file_write_size = 0;
    conf->manager.intercept_errors = 1;
    conf->manager.intercept_404 = 1;
    conf->manager.pass_request_headers = 0;
    conf->manager.pass_request_body = 0;
    conf->manager.force_ranges = 1;

    /* Other bits more specific to the session management module itself */
    // conf->action = { 0, NULL };
    // conf->profile_name = { 0, NULL };
    // conf->valid_redirect_target = { 0, NULL };
    // conf->invalid_redirect_target = { 0, NULL };
    // conf->cookie_id = { 0, NULL };
    conf->oauth_enabled = NGX_CONF_UNSET;
    // conf->session_property = { 0, NULL };

    return conf;
}

/* Odd case, no way to merge strings with NULL using standard ngx defines */
#define ngx_conf_merge_str(conf, prev)             \
    if (conf.data == NULL) {                       \
        if (prev.data != NULL) {                   \
            conf.len = prev.len;                   \
            conf.data = prev.data;                 \
        }                                          \
    }

/**
 * Matching method to merge between multiple location definitions, apparently
 * including core-inherited instances (see note above).
 *
 * @param cf The main configuration object, for reference and allocation.
 * @param parent The configuration instance to inherit from.
 * @param child The configure instance to inherit into.
 * @return A suitable return code for the operation (ok).
 */
static char *ngx_http_session_merge_loc_conf(ngx_conf_t *cf,
                                             void *parent, void *child) {
    ngx_http_session_loc_conf_t *prev = parent;
    ngx_http_session_loc_conf_t *conf = child;

    /* All of these options are sourced from the memcached module */
    ngx_conf_merge_ptr_value(conf->manager.local,
                             prev->manager.local, NULL);
    ngx_conf_merge_value(conf->manager.socket_keepalive,
                              prev->manager.socket_keepalive, 0);
    ngx_conf_merge_uint_value(conf->manager.next_upstream_tries,
                              prev->manager.next_upstream_tries, 0);
    ngx_conf_merge_msec_value(conf->manager.connect_timeout,
                              prev->manager.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->manager.send_timeout,
                              prev->manager.send_timeout, 60000);
    ngx_conf_merge_msec_value(conf->manager.read_timeout,
                              prev->manager.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->manager.next_upstream_timeout,
                              prev->manager.next_upstream_timeout, 0);
    ngx_conf_merge_size_value(conf->manager.buffer_size,
                              prev->manager.buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_bitmask_value(conf->manager.next_upstream,
                                 prev->manager.next_upstream,
                                 NGX_CONF_BITMASK_SET |
                                 NGX_HTTP_UPSTREAM_FT_ERROR |
                                 NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    if ((conf->manager.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) != 0) {
        conf->manager.next_upstream = NGX_CONF_BITMASK_SET |
                                      NGX_HTTP_UPSTREAM_FT_OFF;
    }
    if (conf->manager.upstream == NULL) {
        conf->manager.upstream = prev->manager.upstream;
    }

    /* Also merge the local settings as appropriate */
    ngx_conf_merge_str(conf->action, prev->action);
    ngx_conf_merge_str(conf->profile_name, prev->profile_name);
    ngx_conf_merge_str(conf->valid_redirect_target,
                       prev->valid_redirect_target);
    ngx_conf_merge_str(conf->invalid_redirect_target,
                       prev->invalid_redirect_target);
    ngx_conf_merge_str_value(conf->cookie_id,
                             prev->cookie_id, "sid");
    ngx_conf_merge_value(conf->oauth_enabled, prev->oauth_enabled, NGX_FALSE);
    ngx_conf_merge_str_value(conf->session_property,
                             prev->session_property, "sid");

    return NGX_CONF_OK;
}

/* The module context, provides methods for module definition/configuration */
static ngx_http_module_t ngx_http_session_module_ctx = {
    NULL, NULL,
    NULL, NULL,
    NULL, NULL,
    ngx_http_session_create_loc_conf, ngx_http_session_merge_loc_conf
};

/* Schematic definition of the actual module instance */
ngx_module_t ngx_http_session_module = {
    NGX_MODULE_V1,
    &ngx_http_session_module_ctx,
    ngx_http_session_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* HTTP request translation for the following method */
static const char *get_method_name(ngx_int_t method) {
    switch (method) {
        case NGX_HTTP_GET:
            return "GET";
        case NGX_HTTP_HEAD:
            return "HED";
        case NGX_HTTP_POST:
            return "PST";
        case NGX_HTTP_PUT:
            return "PUT";
        case NGX_HTTP_DELETE:
            return "DEL";
        case NGX_HTTP_MKCOL:
            return "MCL";
        case NGX_HTTP_COPY:
            return "CPY";
        case NGX_HTTP_MOVE:
            return "MOV";
        case NGX_HTTP_OPTIONS:
            return "OPT";
        case NGX_HTTP_PROPFIND:
            return "PFD";
        case NGX_HTTP_PROPPATCH:
            return "PPT";
        case NGX_HTTP_LOCK:
            return "LCK";
        case NGX_HTTP_UNLOCK:
            return "ULK";
        case NGX_HTTP_PATCH:
            return "PCH";
        case NGX_HTTP_TRACE:
            return "TRC";
    }

    return "UNK";
}

/**
 * Request handler for session redirect/verify bound request handling, pulling
 * and verifying session information and then redirecting appropriately.
 *
 * @param req Reference to the associated incoming HTTP request instance.
 * @return Suitable status return based on processing.
 */
static ngx_int_t ngx_http_session_request_handler(ngx_http_request_t *req) {
    ngx_http_session_loc_conf_t *slcf;
    ngx_http_session_request_ctx_t *ctx;
    ngx_int_t la, lb, lc, ld, le;
    ngx_str_t session_id;
    uint8_t *ptr;

    /* Need our original configuration for processing */
    slcf = ngx_http_get_module_loc_conf(req, ngx_http_session_module);

    /* This shouldn't happen (request reset) but just in case... */
    ctx = ngx_http_get_module_ctx(req, ngx_http_session_module);
    if (ctx != NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Based on configuration, determine the inbound session identifier */
    ngx_memzero(&session_id, sizeof(session_id));
    if (slcf->cookie_id.len != 0) {
        /* Actually don't really care about the index, just the value */
        la = ngx_http_parse_multi_header_lines(&(req->headers_in.cookies),
                                               &(slcf->cookie_id), &session_id);
    }
    if ((session_id.len == 0) && (slcf->oauth_enabled)) {
        /* TODO - validate req->headers_in.authorization->value for OAuth */
    }

    /* Create the associated context for tracking the verification request */
    ctx = ngx_pcalloc(req->pool, sizeof(ngx_http_session_request_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* TODO - possible short-cut cache for local redirect/verify? */

    /* And build the outbound verify request */
    ctx->request_length = 4 + 3 + (la = slcf->action.len) +
                              3 + (lb = slcf->profile_name.len) +
                              3 + (lc = session_id.len) +
                              3 + (ld = req->connection->addr_text.len) +
                              7 + (le = req->uri.len);
    if (slcf->sess_req != NGXMGR_SESSION_ACTION) ctx->request_length -= 3;
    ctx->request_content = ngx_pcalloc(req->pool, ctx->request_length + 1);
    if ((ptr = ctx->request_content) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    *((uint32_t *) ptr) = htonl(ctx->request_length - 4);
    *ptr = (uint8_t) slcf->sess_req; ptr += 4;

    if (slcf->sess_req == NGXMGR_SESSION_ACTION) {
        *((uint16_t *) ptr) = htons(la); ptr += 2;
        ngx_memcpy(ptr, slcf->action.data, la); ptr += la;
        *(ptr++) = '\0';
    }
    *((uint16_t *) ptr) = htons(lb); ptr += 2;
    ngx_memcpy(ptr, slcf->profile_name.data, lb); ptr += lb;
    *(ptr++) = '\0';
    *((uint16_t *) ptr) = htons(lc); ptr += 2;
    ngx_memcpy(ptr, session_id.data, lc); ptr += lc;
    *(ptr++) = '\0';
    *((uint16_t *) ptr) = htons(ld); ptr += 2;
    ngx_memcpy(ptr, req->connection->addr_text.data, ld); ptr += ld;
    *(ptr++) = '\0';
    *((uint16_t *) ptr) = htons((le + 4)); ptr += 2;
    ngx_memcpy(ptr, get_method_name(req->method), 3); ptr += 3;
    *(ptr++) = ' ';
    ngx_memcpy(ptr, req->uri.data, le); ptr += le;
    *(ptr++) = '\0';

    /* Attach to the request context */
    ctx->request = req;
    ctx->slcf = slcf;
    ngx_http_set_ctx(req, ctx, ngx_http_session_module);

    /* Generate/push to the upstream data instance, with POST handling */
    return ngx_http_session_create_upstream(slcf, req, ctx);
}

/**
 * Parsing method for the session_redirect directive.  Registers/binds to
 * the upstream instance and registers the session request handler for
 * incoming requests to this location.
 *
 * @param cf The module/location configuration instance reference.
 * @param cmd Reference to the original directives for the module.
 * @param conf Configuration content for the module instance.
 * @return Status result for the configuration parsing/setup.
 */
static char *ngx_http_session_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
                                       void *conf) {
    ngx_http_session_loc_conf_t *slcf = conf;
    ngx_str_t *values = (ngx_str_t *) cf->args->elts;
    ngx_http_core_loc_conf_t *clcf;
    ngx_url_t url;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "*** session manager: redirect for %.*s [to %.*s]",
                   values[1].len, values[1].data,
                   values[2].len, values[2].data);

    /* This directive can only be used once (non-merging) */
    if (slcf->manager.upstream != NULL) {
        return "- duplicate instance specified";
    }

    /* Attach to the defined upstream instance (or error if invalid) */
    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = values[1];
    url.no_resolve = 1;

    slcf->manager.upstream = ngx_http_upstream_add(cf, &url, 0);
    if (slcf->manager.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Underlying command for the request handler */
    slcf->sess_req = NGXMGR_VALIDATE_SESSION;

    /* Store the profile and verified redirect target - @ or get */
    slcf->profile_name = values[2];
    slcf->valid_redirect_target = values[3];

    /* Optionally, store the failure target (error in response if undefined) */
    if (cf->args->nelts > 4) {
        slcf->invalid_redirect_target = values[4];
    }

    /* Insert the request handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_session_request_handler;

    return NGX_CONF_OK;
}

/**
 * Parsing method for the session_verify directive.  Registers/binds to
 * the upstream instance and registers the session request handler for
 * incoming requests to this location.
 *
 * @param cf The module/location configuration instance reference.
 * @param cmd Reference to the original directives for the module.
 * @param conf Configuration content for the module instance.
 * @return Status result for the configuration parsing/setup.
 */
static char *ngx_http_session_verify(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf) {
    ngx_http_session_loc_conf_t *slcf = conf;
    ngx_str_t *values = (ngx_str_t *) cf->args->elts;
    ngx_http_core_loc_conf_t *clcf;
    ngx_url_t url;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "*** session manager: verify for %.*s:%.*s [to %.*s]",
                   values[1].len, values[1].data,
                   values[2].len, values[2].data,
                   values[3].len, values[3].data);

    /* This directive can only be used once (non-merging) */
    if (slcf->manager.upstream != NULL) {
        return "- duplicate instance specified";
    }

    /* Attach to the defined upstream instance (or error if invalid) */
    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = values[1];
    url.no_resolve = 1;

    slcf->manager.upstream = ngx_http_upstream_add(cf, &url, 0);
    if (slcf->manager.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Underlying command for the request handler */
    slcf->sess_req = NGXMGR_VERIFY_SESSION;

    /* Store the profile and verified redirect target - @ or get */
    slcf->profile_name = values[2];
    slcf->valid_redirect_target = values[3];

    /* Optionally, store the failure target (error in response if undefined) */
    if (cf->args->nelts > 4) {
        slcf->invalid_redirect_target = values[4];
    }

    /* Insert the request handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_session_request_handler;

    return NGX_CONF_OK;
}

/**
 * Parsing method for the session_action directive.  Registers/binds to
 * the upstream instance and registers the session request handler for
 * incoming requests to this location.
 *
 * @param cf The module/location configuration instance reference.
 * @param cmd Reference to the original directives for the module.
 * @param conf Configuration content for the module instance.
 * @return Status result for the configuration parsing/setup.
 */
static char *ngx_http_session_action(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf) {
    ngx_http_session_loc_conf_t *slcf = conf;
    ngx_str_t *values = (ngx_str_t *) cf->args->elts;
    ngx_http_core_loc_conf_t *clcf;
    ngx_url_t url;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "*** session manager: action for %.*s:%.*s [%.*s]",
                   values[1].len, values[1].data,
                   values[2].len, values[2].data,
                   values[3].len, values[3].data);

    /* This directive can only be used once (non-merging) */
    if (slcf->manager.upstream != NULL) {
        return "- duplicate instance specified";
    }

    /* Attach to the defined upstream instance (or error if invalid) */
    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = values[1];
    url.no_resolve = 1;

    slcf->manager.upstream = ngx_http_upstream_add(cf, &url, 0);
    if (slcf->manager.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Underlying command for the request handler */
    slcf->sess_req = NGXMGR_SESSION_ACTION;

    /* Store the action and profile */
    slcf->profile_name = values[2];
    slcf->action = values[3];

    /* Insert the request handler */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_session_request_handler;

    return NGX_CONF_OK;
}

/**
 * Parsing method for the session_status directive.  Registers/binds to
 * the upstream instance and registers the status request handler for this
 * location.
 *
 * @param cf The module/location configuration instance reference.
 * @param cmd Reference to the original directives for the module.
 * @param conf Configuration content for the module instance.
 * @return Status result for the configuration parsing/setup.
 */
static char *ngx_http_session_status(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf) {
    ngx_http_session_loc_conf_t *slcf = conf;
    ngx_str_t *values = (ngx_str_t *) cf->args->elts;
    ngx_url_t url;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "*** session status: enabled for %.*s",
                   values[1].len, values[1].data);

    /* This directive can only be used once (non-merging) */
    if (slcf->manager.upstream != NULL) {
        return "- duplicate instance specified";
    }

    /* Attach to the defined upstream instance (or error if invalid) */
    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = values[1];
    url.no_resolve = 1;

    slcf->manager.upstream = ngx_http_upstream_add(cf, &url, 0);
    if (slcf->manager.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    /* TODO - actually implement status console */

    return NGX_CONF_OK;
}
