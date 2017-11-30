#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <unistd.h>
#include "ngx_http_req_status_module.h"
#include "ngx_http_bandwidth_limit_module.h"


#define NGX_HTTP_RPC_CONNECT_DONE          0x0001
#define NGX_HTTP_RPC_SEND_DONE             0x0002
#define NGX_HTTP_RPC_RECV_DONE             0x0004
#define NGX_HTTP_RPC_ALL_DONE              0x0008

#define NGX_HTTP_RPC_LIMITBW		       0x0001


typedef ngx_int_t (*ngx_http_rpc_packet_init_pt)
    (void *rpc_server);
typedef ngx_int_t (*ngx_http_rpc_packet_parse_pt)
    (void *rpc_server);
typedef void (*ngx_http_rpc_packet_clean_pt)
    (void *rpc_server);

static ngx_int_t ngx_http_rpc_handler(ngx_http_request_t *r);
static char *ngx_http_rpc_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_rpc_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_rpc_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_rpc_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_rpc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_rpc_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rpc_init_process(ngx_cycle_t *cycle);

static ngx_rpc_type_conf_t *ngx_http_rpc_get_type_conf(ngx_str_t *str);
static ngx_int_t ngx_http_rpc_add_server(ngx_conf_t *cf, void* conf);

static void ngx_http_rpc_connect_handler(ngx_event_t *event);
static ngx_int_t ngx_http_rpc_peek_one_byte(ngx_connection_t *c);
static ngx_int_t ngx_http_rpc_need_exit();

static void ngx_http_rpc_send_handler(ngx_event_t *event);
static void ngx_http_rpc_recv_handler(ngx_event_t *event);
static void ngx_http_rpc_clear_handler();

static void ngx_http_rpc_ev_handler(ngx_event_t *ev);
static void ngx_http_rpc_clean_event(ngx_http_rpc_server_t *rs);

static ngx_command_t  ngx_http_rpc_commands[] = {
	{ ngx_string("rpc"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
		ngx_http_rpc_server,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL },

	ngx_null_command
};

static ngx_http_module_t  ngx_http_rpc_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_rpc_init,                     /* postconfiguration */

	ngx_http_rpc_create_main_conf,         /* create main configuration */
	ngx_http_rpc_init_main_conf,           /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_rpc_create_loc_conf,          /* create location configuration */
	ngx_http_rpc_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_rpc_module = {
	NGX_MODULE_V1,
	&ngx_http_rpc_module_ctx,           /* module context */
	ngx_http_rpc_commands,              /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	ngx_http_rpc_init_process,             /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


static ngx_rpc_type_conf_t  ngx_rpc_types[] = {

	{ ngx_string("limitbw"),
		NGX_HTTP_RPC_LIMITBW,
		ngx_http_rpc_send_handler,
		ngx_http_rpc_recv_handler },

	{ ngx_null_string,
		0,
		NULL,
        NULL }
};

static ngx_http_rpc_main_conf_t  *rpc_ctx = NULL;
static ngx_uint_t ngx_http_rpc_shm_generation = 0;


static ngx_int_t
ngx_http_rpc_handler(ngx_http_request_t *r)
{
	//ngx_http_rpc_main_conf_t  *rmcf;
	ngx_http_rpc_loc_conf_t  *conf;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_rpc_module);

	return NGX_DECLINED;
}

static char *
ngx_http_rpc_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	u_char			*p, *last;
	time_t			rpc_timeout, rpc_interval;
	ngx_uint_t		i;
	ngx_url_t		u;
	ngx_str_t		*value, s;

	ngx_http_rpc_loc_conf_t *rlcf = conf;

	value = cf->args->elts;
	last = value[1].data + value[1].len;
	if(ngx_strncmp(value[1].data, "http://", 7) == 0) {
		p = value[1].data + 7;
	} else if(ngx_strncmp(value[1].data, "https://", 8) == 0) {
		p = value[1].data + 8;
	} else {
		p = value[1].data;
	}

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url.data = p;
	u.url.len= value[1].len - (p - value[1].data);
	u.default_port = 80;
	u.uri_part = 1;

	if(ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"error: \"%s\" in url \"%V\"", u.err, &value[1]);
			return NGX_CONF_ERROR;
		}
		return NGX_CONF_ERROR;
	}
	if(u.uri.len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "rpc_server: "
				"invalid rpc server, no uri to send");
		return NGX_CONF_ERROR;
	}
	rlcf->rpc_host = u.host;
	rlcf->rpc_port = u.port;
	rlcf->rpc_uri = u.uri;

	rlcf->us.addrs = u.addrs;
	rlcf->us.naddrs = u.naddrs;

	rpc_timeout = 2000;
	rpc_interval = 60000;
	for (i = 2; i < cf->args->nelts; i++) {

		if (ngx_strncmp(value[i].data, "rpc_timeout=", 12) == 0) {

			s.len = value[i].len - 12;
			s.data = &value[i].data[12];

			rpc_timeout = ngx_parse_time(&s, 0);
			if (rpc_timeout == (time_t) NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"rpc_server: invalid parameter:\"%V\"", 
						&value[i]);
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "rpc_interval=", 13) == 0) {

			s.len = value[i].len - 13;
			s.data = &value[i].data[13];
			rpc_interval = ngx_parse_time(&s, 0);
			if (rpc_interval == (time_t) NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"rpc_server: invalid parameter: \"%V\"", 
						&value[i]);
				goto invalid;
			}

			continue;
		}

		if (ngx_strncmp(value[i].data, "rpc_type=", 9) == 0) {
			s.len = value[i].len - 9;
			s.data = value[i].data + 9;

			rlcf->rpc_type_conf = ngx_http_rpc_get_type_conf(&s);
			if (rlcf->rpc_type_conf == NULL) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"rpc_server: rpc_type invalid para: \"%V\"", &value[1]);
				
				goto invalid;
			}

			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"rpc_server: rpc_type invalid para: \"%V\"", &value[i]);

		goto invalid;
	}

	rlcf->rpc_timeout = rpc_timeout;
	rlcf->rpc_interval = rpc_interval;

	if(rlcf->rpc_type_conf == NGX_CONF_UNSET_PTR) {
		rlcf->rpc_type_conf = &ngx_rpc_types[0];
	}

	if(ngx_http_rpc_add_server(cf, conf) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;

invalid:

	return NGX_CONF_ERROR;
}

static ngx_rpc_type_conf_t *
ngx_http_rpc_get_type_conf(ngx_str_t *str)
{
	ngx_uint_t  i;

	for (i = 0; /* void */ ; i++) {

		if (ngx_rpc_types[i].rpc_type == 0) {
			break;
		}

		if (str->len != ngx_rpc_types[i].name.len) {
			continue;
		}

		if (ngx_strncmp(str->data, ngx_rpc_types[i].name.data,
					str->len) == 0)
		{
			return &ngx_rpc_types[i];
		}
	}

	return NULL;
}

static ngx_int_t
ngx_http_rpc_add_server(ngx_conf_t *cf, void* conf)
{
	ngx_http_rpc_server_t			*rs;
	ngx_http_rpc_main_conf_t		*rmcf;
	
	rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_rpc_module);

	rs = ngx_array_push(&rmcf->rpc_servers);
	if(rs == NULL) {
		return NGX_ERROR;
	}

	ngx_memzero(rs, sizeof(ngx_http_rpc_server_t));
	rs->conf = conf;

	return NGX_OK;
}

static void
ngx_http_rpc_ev_handler(ngx_event_t *ev)
{
    ngx_http_rpc_server_t      *rpc_server;
	ngx_http_rpc_loc_conf_t *conf;
	
	if (ngx_http_rpc_need_exit()) {
			return;
	}

    if (!(rpc_ctx->rpc_servers.nelts > 0) ) {
        return;
    }

    rpc_server = ev->data;
    conf = rpc_server->conf;

    ngx_add_timer(ev, conf->rpc_interval);
	ngx_http_rpc_connect_handler(ev);
}

static void 
ngx_http_rpc_connect_handler(ngx_event_t *event)
{
	ngx_int_t	rc;
	ngx_uint_t	keepAlive = 1, keepIdle = 10, keepInterval = 5, keepCount = 2;

	ngx_connection_t		*c;
	//ngx_buf_t				*b;
	ngx_http_upstream_server_t	*us;
	ngx_http_rpc_server_t	*rs;	
	ngx_rpc_type_conf_t		*rf;
	ngx_http_rpc_loc_conf_t *conf;

    rs = event->data;
	conf = rs->conf;
	us = &conf->us;
	rf = conf->rpc_type_conf;

	if (ngx_http_rpc_need_exit()) {
		return;
	}
	if (rs->pc.connection != NULL) {
        c = rs->pc.connection;
        if ((rc = ngx_http_rpc_peek_one_byte(c)) == NGX_OK) {
            goto rpc_connect_done;
        } else {
            ngx_close_connection(c);
            rs->pc.connection = NULL;
        }
    }
	
	ngx_memzero(&rs->pc, sizeof(ngx_peer_connection_t));

	rs->pc.sockaddr = us->addrs[0].sockaddr;
	rs->pc.socklen = us->addrs[0].socklen;
	rs->pc.name = &us->addrs[0].name;

	rs->pc.get = ngx_event_get_peer;
	rs->pc.log = rs->log;
	rs->pc.log_error = NGX_ERROR_ERR;

	rs->pc.cached = 0;
	rs->pc.connection = NULL;
	rc = ngx_event_connect_peer(&rs->pc);

	if (rc == NGX_ERROR || rc == NGX_DECLINED) {
		ngx_log_error(NGX_LOG_ERR, rs->log, 0, "connect server \"%V\" fail:\"%s\"", rs->pc.name, strerror(errno));
		return;
	}
	/* NGX_OK or NGX_AGAIN */

	c = rs->pc.connection;
	c->data = rs;
	c->log = rs->pc.log;
	c->sendfile = 0;
	c->read->log = c->log;
	c->write->log = c->log;
	c->pool = rs->pool;

	//tcp keepalive
	if(setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&keepAlive, sizeof(keepAlive)) == -1) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "setsockopt so_keepalive fail");
	}

	if(setsockopt(c->fd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle)) == -1) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "setsockopt tcp_keepidle fail");
	}

	if(setsockopt(c->fd, SOL_TCP, TCP_KEEPINTVL, (void*)&keepInterval, sizeof(keepInterval)) == -1) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "setsockopt tcp_keepintvl fail");
	}

	if(setsockopt(c->fd, SOL_TCP, TCP_KEEPCNT, (void*)&keepCount, sizeof(keepCount)) == -1) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "setsockopt tcp_keepcnt fail");
	}

rpc_connect_done:
    rs->state = NGX_HTTP_RPC_CONNECT_DONE;
	c->write->handler = rf->send_handler;
	c->read->handler = rf->recv_handler;

    /* The kqueue's loop interface needs it. */
    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }
}
static ngx_int_t
ngx_http_rpc_peek_one_byte(ngx_connection_t *c)
{
	char                            buf[1];
	ngx_int_t                       n;
	ngx_err_t                       err;

	n = recv(c->fd, buf, 1, MSG_PEEK);
	err = ngx_socket_errno;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
			"rpc server recv(): %i, fd: %d",
			n, c->fd);

	if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
		return NGX_OK;
	} else {
		return NGX_ERROR;
	}
}

static void
ngx_http_rpc_send_handler(ngx_event_t *event)
{
	ssize_t						size;
	ngx_buf_t					*b;
	ngx_connection_t			*c;
	ngx_http_rpc_server_t		*rs;

	c = event->data;
	rs = c->data;
	b = rs->sb;
	
	if (ngx_http_rpc_need_exit()) {
		   return;
	}

	if (ngx_http_req_status_send_set_handler(rs) != NGX_OK){
		return;
	}
	if (rs->state != NGX_HTTP_RPC_CONNECT_DONE) {
		if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
			goto rpc_send_fail;
		}

		return;
	}

	while (b->pos < b->last) {

		size = c->send(c, b->pos, b->last - b->pos);

		if(size > 0) {
                   b->pos += size;
		} else if(size == 0 || size == NGX_AGAIN) {
			return;
		} else {
			c->error = 1;
			goto rpc_send_fail;
		}
	}

	if (b->pos == b->last) {
        rs->state = NGX_HTTP_RPC_SEND_DONE;
    }
	b->last = b->pos = b->start;
	return;

rpc_send_fail:
	b->last = b->pos = b->start;
    ngx_http_rpc_clean_event(rs);
}

static void
ngx_http_rpc_recv_handler(ngx_event_t *event)
{
	ssize_t						size, n;
	ngx_buf_t					*b;
	ngx_connection_t			*c;
	ngx_http_rpc_server_t		*rs;
	
	c = event->data;
	rs = c->data;
	b = rs->rb;
	
        if (ngx_http_rpc_need_exit()) {
	    return;
	}

    if (rs->state != NGX_HTTP_RPC_SEND_DONE) {

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto rpc_send_fail;
        }

        return;
    }

	while(1) {
		n = b->end - b->last;
		size = c->recv(c, b->last, n);
                
        if (size > 0) {
           b->last += size;
           continue;
        } else if (size ==0 || size == NGX_AGAIN) {
           if (ngx_http_revc_bandwidth_limit_handler(c) != NGX_OK) {
		       goto rpc_send_fail;
		   }
           break;
        } else {
           c->error = 1;
           goto rpc_send_fail;
        }
	}
	rs->state = NGX_HTTP_RPC_RECV_DONE;
    b->last = b->pos = b->start;
	//ngx_http_rpc_clean_event(rs);
	rs->state = NGX_HTTP_RPC_ALL_DONE;
	return;

rpc_send_fail:   
        b->last = b->pos = b->start;
        ngx_http_rpc_clean_event(rs);
}


static void
ngx_http_rpc_clean_event(ngx_http_rpc_server_t *rs)
{
    ngx_connection_t                    *c;
    ngx_http_rpc_loc_conf_t             *rlf;
    ngx_rpc_type_conf_t                 *cf;

    c = rs->pc.connection;
    rlf = rs->conf;
    cf = rlf->rpc_type_conf;

    if (c) {
            ngx_close_connection(c);
            rs->pc.connection = NULL;
    }
	rs->state = NGX_HTTP_RPC_ALL_DONE;
}


static ngx_int_t
ngx_http_rpc_need_exit()
{

	if (ngx_terminate || ngx_exiting || ngx_quit) {
		ngx_http_rpc_clear_handler();
		return 1;
	}

	return 0;
}

static void
ngx_http_rpc_clear_handler()
{
	ngx_uint_t					i;
	ngx_connection_t			*c;
	ngx_http_rpc_server_t		*rs;
	static ngx_flag_t           has_cleared = 0;

	if(has_cleared || rpc_ctx == NULL ) {
		return ;
	}

	has_cleared = 1;

	rs = rpc_ctx->rpc_servers.elts;

	for(i = 0; i < rpc_ctx->rpc_servers.nelts; i++)
	{
		///del timer event 
        if (rs[i].ev.timer_set) {
		    ngx_del_timer(&rs[i].ev);
	    }
		//close connection
		c = rs[i].pc.connection;
		if(c) {
			ngx_close_connection(c);
			rs[i].pc.connection = NULL;
		}

		if(rs[i].pool != NULL) {
			ngx_destroy_pool(rs[i].pool);
			rs[i].pool = NULL;
		}
	}

	return ;
}

static void *
ngx_http_rpc_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_rpc_main_conf_t	*rmcf;

	rmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rpc_main_conf_t));
	if(rmcf == NULL) {
		return NULL;
	}
	
    if (ngx_array_init(&rmcf->rpc_servers, cf->pool, 16, sizeof(ngx_http_rpc_server_t)) != NGX_OK)
    {
        return NULL;
    }

	return rmcf;
}

static char *
ngx_http_rpc_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_rpc_main_conf_t		*rmcf;

	rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_rpc_module);

	if(rmcf->rpc_servers.nelts > 0) {
		rpc_ctx = rmcf;
	}
	return NGX_CONF_OK;
}

static void *
ngx_http_rpc_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_rpc_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rpc_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->rpc_type_conf = NGX_CONF_UNSET_PTR;
	return conf;
}

static char *
ngx_http_rpc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	/*
	ngx_http_rpc_loc_conf_t  *prev = parent;
	ngx_http_rpc_loc_conf_t  *conf = child;
	*/

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rpc_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_rpc_handler;

	///
	return NGX_OK;
}

static ngx_int_t
ngx_http_rpc_init_process(ngx_cycle_t *cycle)
{
	ngx_uint_t				i;
	ngx_msec_t              t, delay;
	ngx_http_rpc_server_t	*rs;
	ngx_http_rpc_loc_conf_t	*conf;

	if(rpc_ctx == NULL || rpc_ctx->rpc_servers.nelts == 0) {
		return NGX_OK;
	}
	
	
	rs = rpc_ctx->rpc_servers.elts;
	for(i = 0; i < rpc_ctx->rpc_servers.nelts; i++)
	{
		conf = rs[i].conf;
		//init rpc server
		
		rs[i].pool = ngx_create_pool(10 * ngx_pagesize, cycle->log);
		if(rs[i].pool == NULL) {
			return NGX_ERROR;
		}

		rs[i].log = cycle->log;

        rs[i].sb = ngx_create_temp_buf(rs[i].pool, ngx_pagesize);
		if(rs[i].sb == NULL) {
			return NGX_ERROR;
		}

	        
        rs[i].rb = ngx_create_temp_buf(rs[i].pool, ngx_pagesize);
		if(rs[i].rb == NULL) {
			return NGX_ERROR;
		}

		//add timer
		rs[i].ev.handler = ngx_http_rpc_ev_handler;
		rs[i].ev.log = rs[i].log;
		rs[i].ev.data = &rs[i];
		rs[i].ev.timer_set = 0;

	    delay = conf->rpc_interval > 1000 ? conf->rpc_interval : 1000;
	    t = ngx_random() % delay;

		ngx_add_timer(&rs[i].ev, t); 
	}
	
	return NGX_OK;
}
