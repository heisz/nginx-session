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

/* Forward declaration of the directive handlers */
static char *ngx_http_session_set_bitmask(ngx_conf_t *cf, ngx_command_t *cmd,
                                          void *conf);
static char *ngx_http_session_form_parameter(ngx_conf_t *cf, ngx_command_t *cmd,
                                             void *conf);
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

/* Bitmask set for OAuth-based session settings */
/* Note that NGX_CONF_BITMASK_SET is set to 0x01 */
#define NGX_HTTP_OAUTH_HEADER 0x00000002
#define NGX_HTTP_OAUTH_QUERY  0x00000004

static ngx_conf_bitmask_t  ngx_http_session_oauth_masks[] = {
    { ngx_string("header"), NGX_HTTP_OAUTH_HEADER },
    { ngx_string("query"), NGX_HTTP_OAUTH_QUERY },
    { ngx_null_string, 0 }
};

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
      NGX_HTTP_LOC_CONF_OFFSET, 
      offsetof(ngx_http_session_loc_conf_t, cookie_name),
      NULL},

    { ngx_string("session_parameter"),
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET, 
      offsetof(ngx_http_session_loc_conf_t, parameter_name),
      NULL},

    { ngx_string("session_bearer"),
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_ANY,
      ngx_http_session_set_bitmask,
      NGX_HTTP_LOC_CONF_OFFSET, 
      offsetof(ngx_http_session_loc_conf_t, bearer_mode),
      &ngx_http_session_oauth_masks},

    { ngx_string("session_oauth"),
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_ANY,
      ngx_http_session_set_bitmask,
      NGX_HTTP_LOC_CONF_OFFSET, 
      offsetof(ngx_http_session_loc_conf_t, oauth_mode),
      &ngx_http_session_oauth_masks},

    { ngx_string("session_form_parameter"),
      NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
      ngx_http_session_form_parameter,
      NGX_HTTP_LOC_CONF_OFFSET, 
      0, NULL},

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
    // conf->cookie_name = { 0, NULL };
    // conf->parameter_name = { 0, NULL };
    // conf->bearer_mode = 0;
    // conf->oauth_mode = 0;

    return conf;
}

/* Odd case, no way to merge strings with NULL using standard ngx defines */
#define ngx_conf_merge_str(conf, prev)     \
    if (conf.data == NULL) {               \
        if (prev.data != NULL) {           \
            conf.len = prev.len;           \
            conf.data = prev.data;         \
        }                                  \
    }

/* Maybe it's just me, but the standard bitmask handling is messed up too */
static char *ngx_http_session_set_bitmask(ngx_conf_t *cf, ngx_command_t *cmd,
                                          void *conf) {
    ngx_uint_t *np = (ngx_uint_t *) (((char *) conf) + cmd->offset);
    char *err = ngx_conf_set_bitmask_slot(cf, cmd, conf);
    if (err != NULL) return err;

    /* This is the weird part, why doesn't the core method set this if set? */
    *np |= NGX_CONF_BITMASK_SET;

    return NGX_CONF_OK;
}

#define ngx_conf_merge_bitmask(conf, prev) \
    if (conf == 0) conf = prev;

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
    ngx_conf_merge_str(conf->cookie_name, prev->cookie_name);
    ngx_conf_merge_str(conf->parameter_name, prev->parameter_name);
    ngx_conf_merge_bitmask(conf->bearer_mode, prev->bearer_mode);
    ngx_conf_merge_bitmask(conf->oauth_mode, prev->oauth_mode);

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

/* Used in several places */
static ngx_str_t access_token_str = ngx_string("access_token");
static ngx_str_t oauth_token_str = ngx_string("oauth_token");

static char *ngx_http_session_form_parameter(ngx_conf_t *cf, ngx_command_t *cmd,
                                             void *conf) {
    if (cf->args->nelts > 1) {
    } else {
    }

    return NGX_CONF_OK;
}

/* This is less than optimal if multiple parameters enabled so don't do that! */
static void ngx_http_session_find_param(ngx_http_request_t *req,
                                        ngx_str_t *name, ngx_str_t *val) {
    u_char *ptr = req->args.data;
    u_char *last = ptr + req->args.len;
    u_char *amp, *eq;

    for (; ptr < last; ptr++) {
        /* Break out the parameter boundaries (& and =) */
        amp = ngx_strlchr(ptr, last, '&');
        if (amp == NULL) {
            amp = last;
        }
        eq = ngx_strlchr(ptr, last, '=');
        if ((eq == NULL) || (eq > amp)) {
            eq = amp;
        }

        /* This assumes the key is never encoded, don't do that either... */
        if (((eq - ptr) == (int) name->len) &&
                (ngx_strncmp(ptr, name->data, name->len) == 0)) {
            val->data = eq + 1;
            val->len = amp - eq;
            val->data = ngx_pstrdup(req->pool, val);
            if (val->data == NULL) val->len = 0;
            if (val->len != 0) {
                ptr = last = val->data;
                ngx_unescape_uri(&last, &ptr, val->len, NGX_UNESCAPE_URI);
                val->len = last - val->data;
            }
            return;
        }

        ptr = amp;
    }
}

/* Common method to parse OAuth Authorization tokens from headers */
static void ngx_http_session_parse_oauth(ngx_http_request_t *req,
                                         ngx_int_t is_v1, ngx_str_t *val) {
    static ngx_str_t bearer = ngx_string("Bearer ");
    static ngx_str_t oauth = ngx_string("OAuth ");
    ngx_str_t *auth_scheme = (is_v1) ? &oauth : &bearer;
    ngx_str_t auth;
    u_char *ptr;

    /* Quick exit if not of desired scheme, otherwise skip over scheme/space */
    if (req->headers_in.authorization == NULL) return;
    auth = req->headers_in.authorization->value;
    if ((auth.len < auth_scheme->len) ||
            (ngx_strncasecmp(auth.data, auth_scheme->data,
                             auth_scheme->len) != 0)) return;
    auth.data += auth_scheme->len;
    auth.len -= auth_scheme->len;

    while ((auth.len > 0) && isspace(auth.data[0])) {
        auth.data++;
        auth.len--;
    }

    /* For OAuth V2 Bearer scheme, remainder is the token */
    if (!is_v1) {
        /* Note: no whitespace trim, request must be well formed */
        val->data = ngx_pstrdup(req->pool, &auth);
        val->len = auth.len;
        if (val->data == NULL) val->len = 0;
        return;
    }

    /* For OAuth V1, support parameterized and bearer form */
    if (ngx_strnstr(auth.data, "=\"", auth.len) == NULL) {
        /* Note: no futher test/trim, request must be well formed */
        val->data = ngx_pstrdup(req->pool, &auth);
        val->len = auth.len;
        if (val->data == NULL) val->len = 0;
        return;
    }

    /* Note that we just grab valid formatted token, no other validation */
    if ((ptr = ngx_strnstr(auth.data, "oauth_token=\"", auth.len)) != NULL) {
        auth.len -= (ptr - auth.data) + 13;
        auth.data = ptr + 13;

        if ((ptr = ngx_strlchr(auth.data, auth.data + auth.len, '"')) != NULL) {
            val->len = auth.len = ptr - auth.data;
            val->data = ngx_pstrdup(req->pool, &auth);
            if (val->data == NULL) val->len = 0;
        }
    }
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
    /* Note that it might already be available from the rewrite phase TODO */
    ngx_memzero(&session_id, sizeof(session_id));
    if (slcf->cookie_name.len != 0) {
        /* Actually don't really care about the index, just the value */
        la = ngx_http_parse_multi_header_lines(&(req->headers_in.cookies),
                                               &(slcf->cookie_name),
                                               &session_id);
    }
    if ((session_id.len == 0) && (slcf->parameter_name.len != 0)) {
        ngx_http_session_find_param(req, &(slcf->parameter_name), &session_id);
    }
    if ((session_id.len == 0) && (slcf->bearer_mode != 0)) {
        if (((slcf->bearer_mode & NGX_HTTP_OAUTH_HEADER) != 0) ||
                (slcf->bearer_mode == NGX_CONF_BITMASK_SET)) {
            ngx_http_session_parse_oauth(req, NGX_FALSE, &session_id);
        }
        if ((session_id.len == 0) &&
                (((slcf->bearer_mode & NGX_HTTP_OAUTH_QUERY) != 0) ||
                     (slcf->bearer_mode == NGX_CONF_BITMASK_SET))) {
            ngx_http_session_find_param(req, &access_token_str, &session_id);
        }
    }
    if ((session_id.len == 0) && (slcf->oauth_mode != 0)) {
        if (((slcf->oauth_mode & NGX_HTTP_OAUTH_HEADER) != 0) ||
                (slcf->oauth_mode == NGX_CONF_BITMASK_SET)) {
            ngx_http_session_parse_oauth(req, NGX_TRUE, &session_id);
        }
        if ((session_id.len == 0) &&
                (((slcf->oauth_mode & NGX_HTTP_OAUTH_QUERY) != 0) ||
                     (slcf->oauth_mode == NGX_CONF_BITMASK_SET))) {
            ngx_http_session_find_param(req, &oauth_token_str, &session_id);
        }
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
 * Configuration syntax:
 *    session_verify <upstream> <success> [<fail>]
 *    (if fail is missing generates unauthorized condition)
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
