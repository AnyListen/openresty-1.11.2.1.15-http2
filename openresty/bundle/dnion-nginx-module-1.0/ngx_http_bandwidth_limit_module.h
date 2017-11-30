/*
 * Copyright (C) Sogou, Inc
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define LBW_SHM_SIZE	100*1024*1024
#define LBW_MSG_SIZE	1024
#define BLW_BODY_SIZE	1024*1024

typedef struct ngx_http_bandwidth_limit_loc_conf_s ngx_http_bandwidth_limit_loc_conf_t;

typedef struct {
	ngx_uint_t	                          vstride;
	ngx_uint_t	                          v;
}ngx_http_bandwidth_limit_val_t;

typedef struct {
    ngx_rbtree_node_t                     node;

	ngx_msec_t                            limit_interval;
    size_t			                      basic_bandwidth;
    ngx_array_t			                  limit_var;
	ngx_uint_t	                          percent;
	ngx_uint_t                             count;

    size_t			                      limit;
	size_t                                min_rate;
	ngx_msec_t                            last_update;

    ngx_uint_t                            len;
    u_char                                key[0];
} ngx_http_bandwidth_limit_node_t;

typedef struct {
    ngx_rbtree_t                          rbtree;
    ngx_rbtree_node_t                     sentinel;
} ngx_http_bandwidth_limit_sh_t;


typedef struct {
	ngx_buf_t		                       *err_msg;
	ngx_buf_t		                       *body_buf;
} ngx_http_bandwidth_limit_ctx_t;

typedef struct {
	ngx_http_bandwidth_limit_sh_t          sctx;
	ngx_http_bandwidth_limit_ctx_t         ctx;
	ngx_pool_t                             *pool;
} ngx_http_bandwidth_limit_main_conf_t;

struct ngx_http_bandwidth_limit_loc_conf_s {
	ngx_flag_t	                           limit_flag;
};


ngx_int_t ngx_http_revc_bandwidth_limit_handler(ngx_connection_t *c);

