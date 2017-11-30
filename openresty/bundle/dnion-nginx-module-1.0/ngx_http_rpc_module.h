#ifndef _NGX_HTTP_RPC_MODULE_H_INCLUDED_
#define _NGX_HTTP_RPC_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_str_t                              name;

	ngx_uint_t                             rpc_type;

	ngx_event_handler_pt                   send_handler;
	ngx_event_handler_pt                   recv_handler;

} ngx_rpc_type_conf_t;

typedef struct {
	ngx_str_t			rpc_host;
	in_port_t           rpc_port;
	ngx_str_t			rpc_uri;

	ngx_msec_t				rpc_timeout;
	ngx_msec_t					rpc_interval;
	ngx_rpc_type_conf_t			*rpc_type_conf;

	ngx_http_upstream_server_t	us;	
	

} ngx_http_rpc_loc_conf_t;


typedef struct {
	ngx_flag_t					state;

	ngx_pool_t					*pool;
	ngx_log_t					*log;

	ngx_buf_t					*sb;
	ngx_buf_t					*rb;

	ngx_peer_connection_t		pc;
	ngx_http_rpc_loc_conf_t		*conf;
	ngx_event_t                 ev;

}ngx_http_rpc_server_t;


typedef struct {
	ngx_array_t                   rpc_servers;  /* ngx_http_rpc_server_t */

}ngx_http_rpc_main_conf_t;

#endif
