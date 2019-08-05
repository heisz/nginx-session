/*
 * Definitions of the nginx elements for the HTTP session management module.
 *
 * Copyright (C) 2018-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#ifndef _NGX_HTTP_SESSION_MODULE

/* For coding consistency with other libraries */
#ifndef NGX_TRUE
#define NGX_TRUE 1
#endif
#ifndef NGX_FALSE
#define NGX_FALSE 0
#endif

/* Needed for reference in several locations */
extern ngx_module_t ngx_http_session_module;

/* Location configuration details for the module */
typedef struct {
    /* The upstream reference used for the connection to the manager */
    ngx_http_upstream_conf_t manager;

    /* Tags/flags for session instance determination and passing */
    ngx_str_t cookie_id;
    ngx_flag_t oauth_enabled;
    ngx_str_t session_property;

    /* Target redirect for session verified resource access */
    ngx_str_t verify_redirect_target;
} ngx_http_session_loc_conf_t;

/* Associated context information for the upstream manager request handling */
typedef struct {
    /* The initial request that is being authenticated */
    ngx_http_request_t *request;

    /* For efficiency, the associated location configuration instance */
    ngx_http_session_loc_conf_t *slcf;

    /* The outbound manager request content */
    uint8_t *request_content;
    uint32_t request_length;
} ngx_http_session_request_ctx_t;

/* Exposed method to create the upstream request instance */
ngx_int_t ngx_http_session_create_upstream(ngx_http_session_loc_conf_t *smcf,
                                           ngx_http_request_t *req,
                                           ngx_http_session_request_ctx_t *ctx);

#endif
