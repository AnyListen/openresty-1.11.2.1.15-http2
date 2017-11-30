#ifndef _NGX_HTTP_REQ_STATUS_H_INCLUDED_
#define _NGX_HTTP_REQ_STATUS_H_INCLUDED_
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_rpc_module.h"


ngx_int_t ngx_http_req_status_rs_filter(ngx_http_request_t *r);

typedef struct ngx_http_req_status_loc_conf_s ngx_http_req_status_loc_conf_t;

typedef struct {
    ngx_uint_t                      requests;
    ngx_uint_t                      traffic;

    ngx_uint_t                      bandwidth;
    ngx_uint_t                      max_bandwidth;

    ngx_uint_t                      max_active;
} ngx_http_req_status_data_t;

typedef struct {
    ngx_rbtree_node_t               node;
    ngx_queue_t                     queue;

    ngx_uint_t                      count; // ref count

    ngx_http_req_status_data_t      data;

    ngx_uint_t                      active;
    ngx_uint_t                      last_traffic;
    ngx_msec_t                      last_traffic_start;
    ngx_msec_t                      last_traffic_update;

    ngx_uint_t                      len;
    u_char                          key[0];
} ngx_http_req_status_node_t;

typedef struct {
    ngx_rbtree_t                    rbtree;
    ngx_rbtree_node_t               sentinel;
    ngx_queue_t                     queue;
    time_t                          expire_lock;
} ngx_http_req_status_sh_t;

typedef struct {
    ngx_str_t                       *zone_name;
    ngx_http_req_status_node_t      *node;
    ngx_http_req_status_data_t      *pdata;
    ngx_http_req_status_data_t      data[0];
} ngx_http_req_status_print_item_t;

typedef struct {
    ngx_http_req_status_sh_t        *sh;
    ngx_slab_pool_t                 *shpool;
    ngx_shm_zone_t                  *shm_zone;
    ngx_http_complex_value_t        key;
} ngx_http_req_status_zone_t;

typedef struct {
    ngx_http_req_status_zone_t      *zone;
    ngx_http_req_status_node_t      *node;
} ngx_http_req_status_zone_node_t;

typedef struct {
    ngx_array_t                     req_zones;
} ngx_http_req_status_ctx_t;

typedef struct {
    ngx_array_t                     zones;

    ngx_msec_t                      interval;
    time_t                          lock_time;
} ngx_http_req_status_main_conf_t;

struct ngx_http_req_status_loc_conf_s {
    ngx_array_t                     req_zones;
    ngx_http_req_status_loc_conf_t *parent;
};

ngx_int_t ngx_http_req_status_send_set_handler(ngx_http_rpc_server_t	*rpc);

#endif
