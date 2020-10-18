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
static char *ngx_http_session_cookie_flags(ngx_conf_t *cf, ngx_command_t *cmd,
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
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF |
                     NGX_CONF_NOARGS | NGX_CONF_TAKE1,
      ngx_http_session_form_parameter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0, NULL},

    { ngx_string("session_cookie_flags"),
      NGX_HTTP_GLOBAL_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_1MORE,
      ngx_http_session_cookie_flags,
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
    if (conf == NULL) return NGX_CONF_ERROR;

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
    // conf->form_param_name = { 0, NULL };
    conf->form_param_enabled = NGX_CONF_UNSET;
    // conf->session_cookie_flags = { 0, NULL };

    return conf;
}

/* Odd case, no way to merge strings with NULL using standard ngx defines */
#define ngx_sess_conf_merge_str(conf, prev)     \
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

#define ngx_sess_conf_merge_bitmask(conf, prev) \
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
    ngx_sess_conf_merge_str(conf->action, prev->action);
    ngx_sess_conf_merge_str(conf->profile_name, prev->profile_name);
    ngx_sess_conf_merge_str(conf->valid_redirect_target,
                            prev->valid_redirect_target);
    ngx_sess_conf_merge_str(conf->invalid_redirect_target,
                            prev->invalid_redirect_target);
    ngx_sess_conf_merge_str(conf->cookie_name, prev->cookie_name);
    ngx_sess_conf_merge_str(conf->parameter_name, prev->parameter_name);
    ngx_sess_conf_merge_bitmask(conf->bearer_mode, prev->bearer_mode);
    ngx_sess_conf_merge_bitmask(conf->oauth_mode, prev->oauth_mode);
    ngx_sess_conf_merge_str(conf->form_param_name, prev->form_param_name);
    ngx_conf_merge_value(conf->form_param_enabled, prev->form_param_enabled,
                         NGX_CONF_UNSET);
    ngx_sess_conf_merge_str(conf->cookie_flags, prev->cookie_flags);

    return NGX_CONF_OK;
}

/* Handler for processing dynamic session variable references */
static ngx_str_t var_pfx = ngx_string("ngxssn_");
static ngx_int_t ngx_http_session_var(ngx_http_request_t *req,
                                      ngx_http_variable_value_t *var,
                                      uintptr_t data) {
    ngx_str_t *name = (ngx_str_t *) data;
    ngx_int_t len, vlen = name->len - var_pfx.len;
    u_char *ptr, *arg = name->data + var_pfx.len;
    ngx_str_t *attributes = NULL;
    uint16_t l;

    /* Ensure we are in response context and variables are defined */
    if ((attributes = ngx_http_get_session_attributes(req)) == NULL) {
        var->not_found = 1;
        return NGX_OK;
    }

    /* Otherwise parse the attributes for the variable suffix */
    /* Note that the content was validated during the original receipt/copy */
    ptr = (u_char *) attributes->data;
    len = attributes->len;
    while (len > 0) {
        l = ntohs(*((uint16_t *) ptr));
        if ((l == vlen) && (memcmp(ptr + 2, arg, vlen) == 0)) {
            var->data = ptr + l + 5;
            var->len = ntohs(*((uint16_t *) (ptr + l + 3)));
            var->valid = 1;
            var->no_cacheable = 0;
            var->not_found = 0;
            return NGX_OK;
        }

        l += ntohs(*((uint16_t *) (ptr + l + 3))) + 6;
        ptr += l;
        len -= l;
    }

    var->not_found = 1;
    return NGX_OK;
}

static ngx_int_t ngx_http_session_var_init(ngx_conf_t *cf) {
    ngx_http_variable_t *var;

    /* Often see loop over static array, but we have one dynamic instance */
    var = ngx_http_add_variable(cf, &var_pfx,
                                NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_session_var;
    var->data = 0;

    return NGX_OK;
}

/* Used in several places */
static ngx_str_t access_token_str = ngx_string("access_token");
static ngx_str_t oauth_token_str = ngx_string("oauth_token");

/* Internal structure to track form completion and pass session data */
typedef struct {
    /* Marking placeholder, this will be null for form handling */
    ngx_http_request_t *request;

    /* Tracking elements for the body content handler */
    ngx_int_t waiting;
    ngx_int_t finished;

    /* Return information for form parameter information */
    char *id_src;
    ngx_str_t session_id;
} ngx_http_session_form_ctx_t;

/* This is the maximum name/content length for session id parameter */
#define MAX_PARAM_LEN 2048

/* Common common method to extract/decode target query/form parameter */
static int ngx_http_session_extract_val(ngx_http_request_t *req,
                                        u_char *pos, u_char *eq, u_char *last,
                                        ngx_str_t *name, ngx_str_t *val) {
    /* This assumes the key is never encoded (so don't do that!) */
    if (((eq - pos) == (int) name->len) &&
            (ngx_strncmp(pos, name->data, name->len) == 0)) {
        val->data = eq + 1;
        val->len = last - val->data;
        val->data = ngx_pstrdup(req->pool, val);
        if (val->data == NULL) val->len = 0;
        if (val->len != 0) {
            pos = last = val->data;
            ngx_unescape_uri(&last, &pos, val->len, NGX_UNESCAPE_URI);
            val->len = last - val->data;
        }

        return NGX_TRUE;
    }

    return NGX_FALSE;
}

/* Common method for testing/handling the three classes of form parameters */
static void ngx_http_session_parse_form_param(ngx_http_request_t *req,
                                              ngx_http_session_loc_conf_t *slcf,
                                              ngx_http_session_form_ctx_t *fctx,
                                              u_char *pos, u_char *last) {
    u_char *eq;
    if ((last == pos) || ((eq = ngx_strlchr(pos, last, '=')) == NULL)) return;

    if (slcf->form_param_name.len != 0) {
        fctx->id_src = "explicit form parameter";
        if (ngx_http_session_extract_val(req, pos, eq, last,
                                         &(slcf->form_param_name),
                                         &(fctx->session_id))) return;
    }

    if (slcf->form_param_enabled != NGX_CONF_UNSET) {
        if (slcf->parameter_name.len != 0) {
            fctx->id_src = "named query form parameter";
            if (ngx_http_session_extract_val(req, pos, eq, last,
                                             &(slcf->parameter_name),
                                             &(fctx->session_id))) return;
        }
        if (slcf->bearer_mode != 0) {
            fctx->id_src = "oauth bearer form parameter";
            if (ngx_http_session_extract_val(req, pos, eq, last,
                                             &access_token_str,
                                             &(fctx->session_id))) return;
        }
	if (slcf->oauth_mode != 0) {
            fctx->id_src = "oauthv1 form parameter";
            if (ngx_http_session_extract_val(req, pos, eq, last,
                                             &oauth_token_str,
                                             &(fctx->session_id))) return;
	}
    }
}

/* End-of-body processor for reading form parameters */
static void ngx_http_session_post_read(ngx_http_request_t *req) {
    ngx_http_session_loc_conf_t *slcf =
                 ngx_http_get_module_loc_conf(req, ngx_http_session_module);
    ngx_http_session_form_ctx_t *fctx =
                 ngx_http_get_module_ctx(req, ngx_http_session_module);
    u_char buff[MAX_PARAM_LEN], *pos, *amp;
    ngx_int_t buff_len = 0, len;
    ngx_chain_t *cl;
    ngx_buf_t *buf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: post read complete - %s",
                   ((fctx->waiting) ? "waiting" : "initial request"));

    /* Mark finished so handler can exit */
    fctx->finished = 1;

    /* I dunno what this is about but nginx locks up without it... */
    req->main->count--;

    /* Parse the session identifier from the form content (hopefully) */
    if ((req->request_body != NULL) && (req->request_body->bufs != NULL)) {
        for (cl = req->request_body->bufs; cl != NULL; cl = cl->next) {
            buf = cl->buf;
            if (buf->in_file) {
                /* TODO - support this someday, if possible... */
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                               "*** session manager: file buffer encountered");
                break;
            }

            /* Churn on ampersand separator, could be fragments in buffer */
            pos = buf->pos;
            while ((amp = ngx_strlchr(pos, buf->last, '&')) != NULL) {
                len = amp - pos;
                if (buff_len + len > MAX_PARAM_LEN) {
                    /* Overflow (but at end), just discard */
                    buff_len = 0;
                } else {
                    ngx_memcpy(buff + buff_len, pos, len);
                    buff_len += len;
                    ngx_http_session_parse_form_param(req, slcf, fctx, buff,
                                                      buff + buff_len);
                    if (fctx->session_id.len != 0) break;
                    buff_len = 0;
                }

                /* Continue inside current buffer */
                pos = amp + 1;
            }
            if (fctx->session_id.len != 0) break;

            /* Retain leftovers, unless overflow */
            len = buf->last - pos;
            if (buff_len + len > MAX_PARAM_LEN) {
                /* Discard, but leave buffer overflowed to avoid use */
                buff_len = MAX_PARAM_LEN + 1;
            } else if (len > 0) {
                ngx_memcpy(buff + buff_len, pos, len);
                buff_len += len;
            }

            /* Perhaps that's the end of the chain */
            if ((buff_len != 0) && (buff_len <= MAX_PARAM_LEN) &&
                    (cl->next == NULL)) {
                ngx_http_session_parse_form_param(req, slcf, fctx, buff,
                                                  buff + buff_len);
                buff_len = 0;
            }

            if (fctx->session_id.len != 0) break;
        }
    }

    /* If we were in a wait state, clear flag and re-enter the processing */
    if (fctx->waiting) {
        fctx->waiting = NGX_FALSE;
        ngx_http_core_run_phases(req);
    }
}

/* The rewrite handler executes everywhere, fast exit if not location enabled */
static ngx_int_t ngx_http_session_rewrite_handler(ngx_http_request_t *req) {
    static ngx_str_t enc_type = ngx_string("application/x-www-form-urlencoded");
    ngx_http_session_loc_conf_t *slcf;
    ngx_http_session_form_ctx_t *fctx;
    ngx_int_t rc;

    /* If there is a context, we are in the form read cycle, finish! */
    fctx = ngx_http_get_module_ctx(req, ngx_http_session_module);
    if (fctx != NULL) {
        /* Wait or continue basd on completion state */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                       "*** session manager: reentered rewrite handler - %s",
                       ((fctx->finished) ? "finished" : "incomplete"));
        return (fctx->finished) ? NGX_DECLINED : NGX_DONE;
    }

    /* Immediate exit if rewrite not needed specifically for this location */
    slcf = ngx_http_get_module_loc_conf(req, ngx_http_session_module);
    if ((slcf == NULL) ||
            ((slcf->form_param_name.len == 0) && (!slcf->form_param_enabled))) {
        /* Just pass it on to the next handler */
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: location enabled rewrite handling");

    /* Or if it's not actually a form request */
    if ((req->method != NGX_HTTP_POST) && (req->method != NGX_HTTP_PUT)) {
        return NGX_DECLINED;
    }
    if ((req->headers_in.content_type == NULL) ||
           (req->headers_in.content_type->value.data == NULL)) {
        return NGX_DECLINED;
    }
    if ((req->headers_in.content_type->value.len != enc_type.len) ||
            (ngx_strncasecmp(req->headers_in.content_type->value.data,
                             enc_type.data, enc_type.len) != 0)) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                   "*** session manager: reading client body for post params");

    /* Set up for form body reading (handy of pcalloc to clear the flags) */
    fctx = ngx_pcalloc(req->pool, sizeof(ngx_http_session_form_ctx_t));
    if (fctx == NULL) return NGX_ERROR;
    fctx->request = NULL;
    ngx_http_set_ctx(req, fctx, ngx_http_session_module);

    /* Read the body and pass along to the next handler when done */
    rc = ngx_http_read_client_request_body(req, ngx_http_session_post_read);
    if ((rc == NGX_ERROR) || (rc >= NGX_HTTP_SPECIAL_RESPONSE)) return rc;
    if (rc == NGX_AGAIN) {
        /* Not done yet, signal continued form content read */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                       "*** session manager: entering wait state for body");
        fctx->waiting = NGX_TRUE;
        return NGX_DONE;
    }

    return NGX_DECLINED;
}

/* Internal option to globally enable rewrite handler for form input handling */
typedef struct {
    ngx_uint_t form_param_needed;
} ngx_http_session_main_conf_t;

static ngx_int_t ngx_http_session_main_init(ngx_conf_t *cf) {
    ngx_http_session_main_conf_t *smcf;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    /* Do nothing if configuration has not been requested anywhere */
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_session_module);
    if (!smcf->form_param_needed) return NGX_OK;

    /* Otherwise, register our rewrite handler */
    /* Note that this applies globally if any location requests it */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_session_rewrite_handler;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "*** session manager: registered rewrite handler (forms)");

    return NGX_OK;
}

static void *ngx_http_session_create_main_conf(ngx_conf_t *cf) {
    /* Note that form_param_needed is automatically zeroed by pcalloc */
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_session_main_conf_t));
}

static char *ngx_http_session_form_parameter(ngx_conf_t *cf, ngx_command_t *cmd,
                                             void *conf) {
    ngx_str_t *values = (ngx_str_t *) cf->args->elts;
    ngx_http_session_loc_conf_t *slcf = conf;
    ngx_http_session_main_conf_t *smcf;

    /* Parse mode of form parameter support (direct or implied) */
    if (cf->args->nelts > 1) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "*** session manager: form parameter %*s",
                       values[1].len, values[1].data);
        slcf->form_param_name = values[1];
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "*** session manager: form parameter (generic)");
        slcf->form_param_enabled = NGX_TRUE;
    }

    /* Force rewrite handler registration in main configuration completion */
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_session_module);
    smcf->form_param_needed = NGX_TRUE;

    return NGX_CONF_OK;
}

/* Flag bitset for cookie security options */
#define NGX_HTTP_SESSION_COOKIE_HTTPONLY 0x01
#define NGX_HTTP_SESSION_COOKIE_SECURE 0x02
#define NGX_HTTP_SESSION_COOKIE_SAMESITE_MASK 0xF0
#define NGX_HTTP_SESSION_COOKIE_SAMESITE_NONE 0x10
#define NGX_HTTP_SESSION_COOKIE_SAMESITE_LAX 0x20
#define NGX_HTTP_SESSION_COOKIE_SAMESITE_STRICT 0x40

static char *ngx_http_session_cookie_flags(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf) {
    ngx_str_t *values = (ngx_str_t *) cf->args->elts;
    ngx_http_session_loc_conf_t *slcf = conf;
    ngx_uint_t idx, flags = 0;
    u_char *ptr;

    /* Avoid confusion, only set once */
    if (slcf->cookie_flags.len != 0) {
        return "- duplicate session cookie flags specified";
    }

    /* NOTE: need to consider other possible flags:
     *
     *    - Expires - nginx-session is really a session manager (session cookie)
     *                and has its own expiry mechanism
     *    - Max-Age - see above
     *    - Domain - this is a possibility, but should be a separate option
     *    - Path - uuuurrrrgh, this really bit me for SSO!!!!
     */

    /* Otherwise build the flagset */
    /* Note: could care about multiple settings inside, but don't... */
    for (idx = 1; idx < cf->args->nelts; idx++) {
        if ((values[idx].len == 8) &&
            (ngx_strncasecmp(values[idx].data,
                             (u_char *) "httponly", 8) == 0)) {
            flags |= NGX_HTTP_SESSION_COOKIE_HTTPONLY;
        } else if ((values[idx].len == 6) &&
                   (ngx_strncasecmp(values[idx].data,
                                    (u_char *) "secure", 6) == 0)) {
            flags |= NGX_HTTP_SESSION_COOKIE_SECURE;
	} else if ((values[idx].len >= 8) &&
		   (ngx_strncasecmp(values[idx].data,
				    (u_char *) "samesite", 8) == 0)) {
            flags &= ~NGX_HTTP_SESSION_COOKIE_SAMESITE_MASK;
            if (values[idx].len == 8) {
                flags |= NGX_HTTP_SESSION_COOKIE_SAMESITE_NONE;
            } else if ((values[idx].len == 13) &&
                       (ngx_strncasecmp(values[idx].data + 8,
                                        (u_char *) "=none", 5) == 0)) {
                flags |= NGX_HTTP_SESSION_COOKIE_SAMESITE_NONE;
            } else if ((values[idx].len == 12) &&
                       (ngx_strncasecmp(values[idx].data + 8,
                                        (u_char *) "=lax", 4) == 0)) {
                flags |= NGX_HTTP_SESSION_COOKIE_SAMESITE_LAX;
            } else if ((values[idx].len == 15) &&
                       (ngx_strncasecmp(values[idx].data + 8,
                                        (u_char *) "=strict", 7) == 0)) {
                flags |= NGX_HTTP_SESSION_COOKIE_SAMESITE_STRICT;
            } else {
                return "- invalid session cookie samesite flag specified";
            }
        } else {
            return "- invalid session cookie flags specified";
        }
    }

    /* And translate it into the flag string */
    slcf->cookie_flags.len = 
             ((flags & NGX_HTTP_SESSION_COOKIE_HTTPONLY) ? 10 : 0) +
             ((flags & NGX_HTTP_SESSION_COOKIE_SECURE) ? 8 : 0) +
             ((flags & NGX_HTTP_SESSION_COOKIE_SAMESITE_NONE) ? 15 : 0) +
             ((flags & NGX_HTTP_SESSION_COOKIE_SAMESITE_LAX) ? 14 : 0) +
             ((flags & NGX_HTTP_SESSION_COOKIE_SAMESITE_STRICT) ? 17 : 0);
    slcf->cookie_flags.data = ngx_pcalloc(cf->pool, slcf->cookie_flags.len + 1);
    if (slcf->cookie_flags.data == NULL) return "memory allocation failure";

    /* Could have just used strcpy but meh */
    ptr = slcf->cookie_flags.data;
    if (flags & NGX_HTTP_SESSION_COOKIE_HTTPONLY) {
        ngx_memcpy(ptr, "; HttpOnly", 10); ptr += 10;
    }
    if (flags & NGX_HTTP_SESSION_COOKIE_SECURE) {
        ngx_memcpy(ptr, "; Secure", 8); ptr += 8;
    }
    if (flags & NGX_HTTP_SESSION_COOKIE_SAMESITE_NONE) {
        ngx_memcpy(ptr, "; SameSite=None", 15); ptr += 15;
    }
    if (flags & NGX_HTTP_SESSION_COOKIE_SAMESITE_LAX) {
        ngx_memcpy(ptr, "; SameSite=Lax", 14); ptr += 14;
    }
    if (flags & NGX_HTTP_SESSION_COOKIE_SAMESITE_STRICT) {
        ngx_memcpy(ptr, "; SameSite=Strict", 17); ptr += 17;
    }

    return NGX_CONF_OK;
}

/* The module context, provides methods for module definition/configuration */
static ngx_http_module_t ngx_http_session_module_ctx = {
    ngx_http_session_var_init, ngx_http_session_main_init,
    ngx_http_session_create_main_conf, NULL,
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

        eq = ngx_strlchr(ptr, amp, '=');
        if (eq != NULL) {
            if (ngx_http_session_extract_val(req, ptr, eq, last,
                                             name, val)) return;
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
    ngx_http_session_form_ctx_t *fctx;
    ngx_int_t la, lb, lc, ld, le;
    ngx_str_t session_id;
    char *id_src = "n/a";
    uint8_t *ptr;

    /* Need our original configuration for processing */
    slcf = ngx_http_get_module_loc_conf(req, ngx_http_session_module);

    /* If there is a form context, it may contain our session identifier */
    ngx_memzero(&session_id, sizeof(session_id));
    fctx = ngx_http_get_module_ctx(req, ngx_http_session_module);
    if ((fctx != NULL) && (fctx->session_id.len != 0)) {
        id_src = fctx->id_src;
        session_id = fctx->session_id;
    }

    /* Based on configuration, determine the inbound session identifier */
    /* Of course, this presumes that the parameter wasn't pulled from post */
    if ((session_id.len == 0) && (slcf->cookie_name.len != 0)) {
        /* Actually don't really care about the index, just the value */
        la = ngx_http_parse_multi_header_lines(&(req->headers_in.cookies),
                                               &(slcf->cookie_name),
                                               &session_id);
        id_src = "cookie";
    }
    if ((session_id.len == 0) && (slcf->parameter_name.len != 0)) {
        ngx_http_session_find_param(req, &(slcf->parameter_name), &session_id);
        id_src = "query parameter";
    }
    if ((session_id.len == 0) && (slcf->bearer_mode != 0)) {
        if (((slcf->bearer_mode & NGX_HTTP_OAUTH_HEADER) != 0) ||
                (slcf->bearer_mode == NGX_CONF_BITMASK_SET)) {
            ngx_http_session_parse_oauth(req, NGX_FALSE, &session_id);
            id_src = "oauth bearer authorization";
        }
        if ((session_id.len == 0) &&
                (((slcf->bearer_mode & NGX_HTTP_OAUTH_QUERY) != 0) ||
                     (slcf->bearer_mode == NGX_CONF_BITMASK_SET))) {
            ngx_http_session_find_param(req, &access_token_str, &session_id);
            id_src = "oauth bearer query parameter";
        }
    }
    if ((session_id.len == 0) && (slcf->oauth_mode != 0)) {
        if (((slcf->oauth_mode & NGX_HTTP_OAUTH_HEADER) != 0) ||
                (slcf->oauth_mode == NGX_CONF_BITMASK_SET)) {
            ngx_http_session_parse_oauth(req, NGX_TRUE, &session_id);
            id_src = "oauthv1 authorization";
        }
        if ((session_id.len == 0) &&
                (((slcf->oauth_mode & NGX_HTTP_OAUTH_QUERY) != 0) ||
                     (slcf->oauth_mode == NGX_CONF_BITMASK_SET))) {
            ngx_http_session_find_param(req, &oauth_token_str, &session_id);
            id_src = "oauthv1 query parameter";
        }
    }

    /* Log enough to know it, but not be a security violation */
    if (session_id.len != 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                       "*** session manager: found session id: len %d, from %s",
                       (int) session_id.len, id_src);
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, req->connection->log, 0,
                       "*** session manager: no session id found");
    }

    /* Create the associated context for tracking the verification request */
    ctx = ngx_pcalloc(req->pool, sizeof(ngx_http_session_request_ctx_t));
    if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

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
 * Configuration syntax:
 *    session_redirect <upstream> <profile> <valid> [<invalid>]
 *    (if <invalid> is missing generates unauthorized condition)
 *
 * Used to do a quick redirection based on the validity of the session or
 * provide a simple access wrapping of a protected resource.
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
                   "*** session manager: redirect for %*s [to %*s]",
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
 *    session_verify <upstream> <profile> <valid> [<invalid>]
 *    (if <invalid> is missing generates unauthorized condition)
 *
 * Unlike redirect, verify requests can be redirected by the profile itself.
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
                   "*** session manager: verify for %*s:%*s [to %*s]",
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
 * Configuration syntax:
 *    session_action <upstream> <profile> <action>
 *    (if <invalid> is missing generates unauthorized condition)
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
                   "*** session manager: action for %*s:%*s [%*s]",
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
                   "*** session status: enabled for %*s",
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
