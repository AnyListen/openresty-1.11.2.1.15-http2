#include <nginx.h>
#include "ngx_http_gslb_check_module.h"


typedef struct ngx_http_gslb_check_peer_s ngx_http_gslb_check_peer_t;
typedef struct ngx_http_gslb_check_srv_conf_s ngx_http_gslb_check_srv_conf_t;
typedef struct ngx_http_gslb_bad_peer_s ngx_http_gslb_bad_peer_t;
typedef struct {
    ngx_buf_t                                send;
    ngx_buf_t                                recv;

    ngx_uint_t                               state;
    ngx_http_status_t                        status;

    ngx_uint_t                               parse_state;
	ngx_int_t								 content_len;

} ngx_http_gslb_check_ctx_t;

struct ngx_http_gslb_bad_peer_s{
    ngx_rbtree_node_t   node;
    ngx_str_t       host;
    in_addr_t       addr;  // as rbtree key
	ngx_queue_t		q;
};

typedef struct {
    ngx_shmtx_t                              mutex;
    ngx_shmtx_sh_t                           lock;

    ngx_pid_t                                owner;

    ngx_msec_t                               access_time;

	//add by lhc
	ngx_uint_t								 failed;

	//bad peers
	ngx_rbtree_t							 *down_peers;
	ngx_rbtree_node_t						 *down_peers_sentinel;
	ngx_queue_t								 busy;
	ngx_queue_t								 idle;

    struct sockaddr                         *sockaddr;
    socklen_t                                socklen;

} ngx_http_gslb_check_peer_shm_t;

typedef struct {
    ngx_uint_t                               generation;
    ngx_uint_t                               checksum;
    ngx_uint_t                               number;

    ngx_http_gslb_check_peer_shm_t       peers[1];
} ngx_http_gslb_check_peers_shm_t;


#define NGX_HTTP_CHECK_CONNECT_DONE          0x0001
#define NGX_HTTP_CHECK_SEND_DONE             0x0002
#define NGX_HTTP_CHECK_RECV_DONE             0x0004
#define NGX_HTTP_CHECK_ALL_DONE              0x0008


#define NGX_PARSE_STATUS_LINE_DONE			 0x0001
#define NGX_PARSE_HTTP_HEADER_DONE	 		 0x0002
#define NGX_PARSE_ALL_DONE			 		 0x0004


typedef ngx_int_t (*ngx_http_gslb_check_packet_init_pt) (ngx_http_gslb_check_peer_t *peer);
typedef ngx_int_t (*ngx_http_gslb_check_packet_parse_pt) (ngx_http_gslb_check_peer_t *peer);
typedef void (*ngx_http_gslb_check_packet_clean_pt) (ngx_http_gslb_check_peer_t *peer);

struct ngx_http_gslb_check_peer_s {
    ngx_flag_t                               state;
    ngx_pool_t                              *pool;
    ngx_uint_t                               index;
    ngx_uint_t                               max_busy;
    //ngx_str_t                               *gslb_name;
    //ngx_addr_t                              *check_peer_addr;
    ngx_addr_t                              *peer_addr;
    ngx_event_t                              check_ev;
    ngx_event_t                              check_timeout_ev;
    ngx_peer_connection_t                    pc;

    void                                    *check_data;
    ngx_event_handler_pt                     send_handler;
    ngx_event_handler_pt                     recv_handler;

    ngx_http_gslb_check_packet_init_pt   init;
    ngx_http_gslb_check_packet_parse_pt  parse;
    ngx_http_gslb_check_packet_clean_pt  reinit;

    ngx_http_gslb_check_peer_shm_t      *shm;
    ngx_http_gslb_check_srv_conf_t      *conf;
};


typedef struct {
    ngx_str_t                                check_shm_name;
    ngx_uint_t                               checksum;
    ngx_array_t                              peers;
	///
	ngx_shm_zone_t							*shm_zone;
	///

    ngx_http_gslb_check_peers_shm_t     *peers_shm;
} ngx_http_gslb_check_peers_t;


#define NGX_HTTP_CHECK_TCP                   0x0001
#define NGX_HTTP_CHECK_HTTP                  0x0002

typedef struct {
    ngx_uint_t                               type;

    ngx_str_t                                name;

    ngx_str_t                                default_send;

    ngx_event_handler_pt                     send_handler;
    ngx_event_handler_pt                     recv_handler;

    ngx_http_gslb_check_packet_init_pt   init;
    ngx_http_gslb_check_packet_parse_pt  parse;
    ngx_http_gslb_check_packet_clean_pt  reinit;

    unsigned need_pool;
    unsigned need_keepalive;
} ngx_check_conf_t;

typedef struct {
    ngx_uint_t                               check_shm_size;
    ngx_http_gslb_check_peers_t         	*peers;
} ngx_http_gslb_check_main_conf_t;


struct ngx_http_gslb_check_srv_conf_s {
    ngx_uint_t                               port;
    ngx_msec_t                               check_interval;
    ngx_msec_t                               check_timeout;
    ngx_uint_t                               check_keepalive_requests;

    ngx_check_conf_t                        *check_type_conf;
    ngx_str_t                                send;
};


static ngx_int_t ngx_http_gslb_check_add_peer(ngx_conf_t *cf, ngx_str_t* host);

static ngx_int_t ngx_http_gslb_check_add_timers(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_gslb_check_peek_one_byte(ngx_connection_t *c);

static void ngx_http_gslb_check_begin_handler(ngx_event_t *event);
static void ngx_http_gslb_check_connect_handler(ngx_event_t *event);

static void ngx_http_gslb_check_peek_handler(ngx_event_t *event);

static void ngx_http_gslb_check_send_handler(ngx_event_t *event);
static void ngx_http_gslb_check_recv_handler(ngx_event_t *event);

static void ngx_http_gslb_check_discard_handler(ngx_event_t *event);
static void ngx_http_gslb_check_dummy_handler(ngx_event_t *event);

static ngx_int_t ngx_http_gslb_check_http_init( ngx_http_gslb_check_peer_t *peer);
static ngx_int_t ngx_http_gslb_check_http_parse( ngx_http_gslb_check_peer_t *peer);
static ngx_int_t ngx_http_gslb_check_parse_status_line( ngx_http_gslb_check_ctx_t *ctx, ngx_buf_t *b, ngx_http_status_t *status);
static void ngx_http_gslb_check_http_reinit( ngx_http_gslb_check_peer_t *peer);

static void ngx_http_gslb_check_status_update( ngx_http_gslb_check_peer_t *peer, ngx_int_t result);

static void ngx_http_gslb_check_clean_event( ngx_http_gslb_check_peer_t *peer);

static void ngx_http_gslb_check_timeout_handler(ngx_event_t *event);
static void ngx_http_gslb_check_finish_handler(ngx_event_t *event);

static ngx_int_t ngx_http_gslb_check_need_exit();
static void ngx_http_gslb_check_clear_all_events();

static ngx_check_conf_t *ngx_http_get_check_type_conf(ngx_str_t *str);

static char *ngx_http_gslb_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_gslb_check_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_gslb_check_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_gslb_check_create_srv_conf(ngx_conf_t *cf);

#define SHM_NAME_LEN 256

static char *ngx_http_gslb_check_init_shm(ngx_conf_t *cf, void *conf);

static ngx_int_t ngx_http_gslb_check_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool, ngx_uint_t generation);

static ngx_int_t ngx_http_gslb_check_init_shm_peer(
    ngx_http_gslb_check_peer_shm_t *peer_shm,
    ngx_http_gslb_check_peer_shm_t *opeer_shm,
    ngx_slab_pool_t *shpool, ngx_pool_t *pool, ngx_str_t *peer_name);

static ngx_int_t ngx_http_gslb_check_init_shm_zone( ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t ngx_http_gslb_check_init_process(ngx_cycle_t *cycle);

static ngx_http_gslb_bad_peer_t *ngx_http_gslb_get_idle_bad_peer(ngx_queue_t *busy, ngx_queue_t *idle);
static ngx_http_gslb_bad_peer_t * ngx_http_gslb_lookup_bad_peer(ngx_rbtree_t *tree, in_addr_t addr);

static ngx_command_t  ngx_http_gslb_check_commands[] = {

    { ngx_string("gslb_check"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_gslb_check,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("gslb_check_keepalive_requests"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_gslb_check_srv_conf_t, check_keepalive_requests),
      NULL },

    { ngx_string("gslb_check_http_send"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_gslb_check_srv_conf_t, send),
      NULL },
};


static ngx_http_module_t  ngx_http_gslb_check_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    ngx_http_gslb_check_create_main_conf,	/* create main configuration */
    ngx_http_gslb_check_init_main_conf,  	/* init main configuration */

    ngx_http_gslb_check_create_srv_conf, 	/* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,									/* create location configuration */
    NULL									/* merge location configuration */
};


ngx_module_t  ngx_http_gslb_check_module = {
    NGX_MODULE_V1,
    &ngx_http_gslb_check_module_ctx,   /* module context */
    ngx_http_gslb_check_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_gslb_check_init_process,  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_check_conf_t  ngx_check_types[] = {

    { NGX_HTTP_CHECK_TCP,
      ngx_string("tcp"),
      ngx_null_string,
      ngx_http_gslb_check_peek_handler,
      ngx_http_gslb_check_peek_handler,
      NULL,
      NULL,
      NULL,
      0,
      1 },

    { NGX_HTTP_CHECK_HTTP,
      ngx_string("http"),
      ngx_string("GET / HTTP/1.0\r\n\r\n"),
      ngx_http_gslb_check_send_handler,
      ngx_http_gslb_check_recv_handler,
      ngx_http_gslb_check_http_init,
      ngx_http_gslb_check_http_parse,
      ngx_http_gslb_check_http_reinit,
      1,
      0 },

    { 0,
      ngx_null_string,
      ngx_null_string,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      0,
      0 }
};

static ngx_uint_t ngx_http_gslb_check_shm_generation = 0;
static ngx_http_gslb_check_peers_t *check_peers_ctx = NULL;


static ngx_int_t ngx_http_gslb_check_add_peer(ngx_conf_t *cf, ngx_str_t* host)
{
	ngx_uint_t						i;
	ngx_url_t						 u;
    ngx_http_gslb_check_peer_t       *peer;
    ngx_http_gslb_check_peers_t      *peers;
    ngx_http_gslb_check_srv_conf_t   *gcscf;
    ngx_http_gslb_check_main_conf_t  *gcmcf;


    gcscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_gslb_check_module);

    gcmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_gslb_check_module);
    peers = gcmcf->peers;

	///parse host 
	ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = *host;
    u.default_port = 80; 
    if(ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if(u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in check host \"%V\" ", u.err, &u.url);
        }
        return NGX_ERROR;
    }

	for(i = 0; i < u.naddrs; i++)
	{
		peer = ngx_array_push(&peers->peers);
		if (peer == NULL) {
			return NGX_ERROR;
		}

		ngx_memzero(peer, sizeof(ngx_http_gslb_check_peer_t));

		peer->index = peers->peers.nelts - 1;
		peer->peer_addr = &u.addrs[i];
		peer->conf = gcscf;

		peers->checksum += ngx_murmur_hash2(peer->peer_addr->name.data, peer->peer_addr->name.len);

	}
    return NGX_OK;
}


ngx_uint_t ngx_http_gslb_check_peer_down(in_addr_t addr)
{
	ngx_uint_t				  i;
	ngx_http_gslb_bad_peer_t  *p;
	ngx_uint_t				  count;

	count = 0;	
    ngx_http_gslb_check_peer_t      *peer;
    ngx_http_gslb_check_peers_t     *peers;

	peers = check_peers_ctx;

	if(peers == NULL){
		return 0;
	}

	peer = peers->peers.elts;

	for (i = 0; i < peers->peers.nelts; i++) {
		ngx_shmtx_lock(&peer[i].shm->mutex);

		if(peer[i].shm->failed){
			count ++;
			ngx_shmtx_unlock(&peer[i].shm->mutex);
			continue;
		}
		p = ngx_http_gslb_lookup_bad_peer(peer[i].shm->down_peers, addr);
		if(p != NULL) {
			ngx_shmtx_unlock(&peer[i].shm->mutex);
			return 0;
		}
		ngx_shmtx_unlock(&peer[i].shm->mutex);
	}

	//如果所有peer全部连接有问题,那就不能够随意调度
	//即认为节点都被禁用了
	if(count == peers->peers.nelts){
		return 1;
	}

	return 1;
}

static ngx_int_t
ngx_http_gslb_check_add_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t                           i;
    ngx_msec_t                           t, delay;
    ngx_check_conf_t                    *cf;
    ngx_http_gslb_check_peer_t      *peer;
    ngx_http_gslb_check_peers_t     *peers;
    ngx_http_gslb_check_srv_conf_t  *gcscf;
    ngx_http_gslb_check_peer_shm_t  *peer_shm;
    ngx_http_gslb_check_peers_shm_t *peers_shm;

    peers = check_peers_ctx;
    if (peers == NULL) {
        return NGX_OK;
    }

    peers_shm = peers->peers_shm;
    if (peers_shm == NULL) {
        return NGX_OK;
    }

    srandom(ngx_pid);

    peer = peers->peers.elts;
    peer_shm = peers_shm->peers;

    for (i = 0; i < peers->peers.nelts; i++) {
        peer[i].shm = &peer_shm[i];

        peer[i].check_ev.handler = ngx_http_gslb_check_begin_handler;
        peer[i].check_ev.log = cycle->log;
        peer[i].check_ev.data = &peer[i];
        peer[i].check_ev.timer_set = 0;

        peer[i].check_timeout_ev.handler = ngx_http_gslb_check_timeout_handler;
        peer[i].check_timeout_ev.log = cycle->log;
        peer[i].check_timeout_ev.data = &peer[i];
        peer[i].check_timeout_ev.timer_set = 0;

        gcscf = peer[i].conf;
        cf = gcscf->check_type_conf;

        if (cf->need_pool) {
            peer[i].pool = ngx_create_pool(ngx_pagesize, cycle->log);
            if (peer[i].pool == NULL) {
                return NGX_ERROR;
            }
        }

        peer[i].send_handler = cf->send_handler;
        peer[i].recv_handler = cf->recv_handler;

        peer[i].init = cf->init;
        peer[i].parse = cf->parse;
        peer[i].reinit = cf->reinit;

        /*
         * We add a random start time here, since we don't want to trigger
         * the check events too close to each other at the beginning.
         */
        delay = gcscf->check_interval > 1000 ? gcscf->check_interval : 1000;
        t = ngx_random() % delay;

        ngx_add_timer(&peer[i].check_ev, t);
    }

    return NGX_OK;
}


static void
ngx_http_gslb_check_begin_handler(ngx_event_t *event)
{
    ngx_msec_t                           interval;
    ngx_http_gslb_check_peer_t      *peer;
    ngx_http_gslb_check_peers_t     *peers;
    ngx_http_gslb_check_srv_conf_t  *gcscf;
    ngx_http_gslb_check_peers_shm_t *peers_shm;

    if (ngx_http_gslb_check_need_exit()) {
        return;
    }

    peers = check_peers_ctx;
    if (peers == NULL) {
        return;
    }

    peers_shm = peers->peers_shm;
    if (peers_shm == NULL) {
        return;
    }

    peer = event->data;
    gcscf = peer->conf;

    ngx_add_timer(event, gcscf->check_interval / 2);

    /* This process is processing this peer now. */

    if ((peer->shm->owner == ngx_pid  ||
        (peer->pc.connection != NULL) ||
        peer->check_timeout_ev.timer_set)) {
        return;
    }

    interval = ngx_current_msec - peer->shm->access_time;
    
    ngx_shmtx_lock(&peer->shm->mutex);

    if (peers_shm->generation != ngx_http_gslb_check_shm_generation) {
        ngx_shmtx_unlock(&peer->shm->mutex);
        return;
    }

    if ((interval >= gcscf->check_interval)
         && (peer->shm->owner == NGX_INVALID_PID))
    {
        peer->shm->owner = ngx_pid;

    } else if (interval >= (gcscf->check_interval << 4)) {

        /*
         * If the check peer has been untouched for 2^4 times of
         * the check interval, activate the current timer.
         * Sometimes, the checking process may disappear
         * in some circumstances, and the clean event will never
         * be triggered.
         */
        peer->shm->owner = ngx_pid;
        peer->shm->access_time = ngx_current_msec;
    }

    ngx_shmtx_unlock(&peer->shm->mutex);

    if (peer->shm->owner == ngx_pid) {
        ngx_http_gslb_check_connect_handler(event);
    }
}


static void
ngx_http_gslb_check_connect_handler(ngx_event_t *event)
{
    ngx_int_t                            rc;
    ngx_connection_t                    *c;
    ngx_http_gslb_check_peer_t      *peer;
    ngx_http_gslb_check_srv_conf_t  *gcscf;

    if (ngx_http_gslb_check_need_exit()) {
        return;
    }

    peer = event->data;
    gcscf = peer->conf;

    if (peer->pc.connection != NULL) {
        c = peer->pc.connection;
        if ((rc = ngx_http_gslb_check_peek_one_byte(c)) == NGX_OK) {
            goto gslb_check_connect_done;
        } else {
            ngx_close_connection(c);
            peer->pc.connection = NULL;
        }
    }
    ngx_memzero(&peer->pc, sizeof(ngx_peer_connection_t));

    peer->pc.sockaddr = peer->peer_addr->sockaddr;
    peer->pc.socklen = peer->peer_addr->socklen;
    peer->pc.name = &peer->peer_addr->name;

    peer->pc.get = ngx_event_get_peer;
    peer->pc.log = event->log;
    peer->pc.log_error = NGX_ERROR_ERR;

    peer->pc.cached = 0;
    peer->pc.connection = NULL;

    rc = ngx_event_connect_peer(&peer->pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_http_gslb_check_status_update(peer,0);
        return;
    }

    /* NGX_OK or NGX_AGAIN */
    c = peer->pc.connection;
    c->data = peer;
    c->log = peer->pc.log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->pool = peer->pool;

gslb_check_connect_done:
    peer->state = NGX_HTTP_CHECK_CONNECT_DONE;

    c->write->handler = peer->send_handler;
    c->read->handler = peer->recv_handler;

    ngx_add_timer(&peer->check_timeout_ev, gcscf->check_timeout);

    /* The kqueue's loop interface needs it. */
    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }
}

static ngx_int_t
ngx_http_gslb_check_peek_one_byte(ngx_connection_t *c)
{
    char                            buf[1];
    ngx_int_t                       n;
    ngx_err_t                       err;

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                   "http check gslb recv(): %i, fd: %d",
                   n, c->fd);

    if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}

static void
ngx_http_gslb_check_peek_handler(ngx_event_t *event)
{
    ngx_connection_t               *c;
    ngx_http_gslb_check_peer_t *peer;

    if (ngx_http_gslb_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    if (ngx_http_gslb_check_peek_one_byte(c) == NGX_OK) {
        ngx_http_gslb_check_status_update(peer,1);

    } else {
        c->error = 1;
        ngx_http_gslb_check_status_update(peer,0);
    }

    ngx_http_gslb_check_clean_event(peer);

    ngx_http_gslb_check_finish_handler(event);
}


static void
ngx_http_gslb_check_discard_handler(ngx_event_t *event)
{
    u_char                          buf[4096];
    ssize_t                         size;
    ngx_connection_t               *c;
    ngx_http_gslb_check_peer_t *peer;

    c = event->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "gslb check discard handler");

    if (ngx_http_gslb_check_need_exit()) {
        return;
    }

    peer = c->data;

    while (1) {
        size = c->recv(c, buf, 4096);

        if (size > 0) {
            continue;

        } else if (size == NGX_AGAIN) {
            break;

        } else {
            if (size == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "peer closed its half side of the connection");
            }

            goto check_discard_fail;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto check_discard_fail;
    }

    return;

 check_discard_fail:
    c->error = 1;
    ngx_http_gslb_check_clean_event(peer);
}


static void
ngx_http_gslb_check_dummy_handler(ngx_event_t *event)
{
    return;
}


static void
ngx_http_gslb_check_send_handler(ngx_event_t *event)
{
    ssize_t                         size;
    ngx_connection_t               *c;
    ngx_http_gslb_check_ctx_t  *ctx;
    ngx_http_gslb_check_peer_t *peer;

    if (ngx_http_gslb_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0, "check pool NULL with peer: %V ", &peer->peer_addr->name);
        goto check_send_fail;
    }

    if (peer->state != NGX_HTTP_CHECK_CONNECT_DONE) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "check handle write event error with peer: %V ", &peer->peer_addr->name);

            goto check_send_fail;
        }

        return;
    }

    if (peer->check_data == NULL) {

        peer->check_data = ngx_pcalloc(peer->pool, sizeof(ngx_http_gslb_check_ctx_t));
        if (peer->check_data == NULL) {
            goto check_send_fail;
        }

        if (peer->init == NULL || peer->init(peer) != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, event->log, 0, "check init error with peer: %V ", &peer->peer_addr->name);

            goto check_send_fail;
        }
    }

    ctx = peer->check_data;

    while (ctx->send.pos < ctx->send.last) {
        size = c->send(c, ctx->send.pos, ctx->send.last - ctx->send.pos);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >=0) ? 0 : ngx_socket_errno;
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, err,
                       "http check send size: %z, total: %z",
                       size, ctx->send.last - ctx->send.pos);
        }
#endif

        if (size > 0) {
            ctx->send.pos += size;
        } else if (size == 0 || size == NGX_AGAIN) {
            return;
        } else {
            c->error = 1;
            goto check_send_fail;
        }
    }

    if (ctx->send.pos == ctx->send.last) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http check send done.");
        peer->state = NGX_HTTP_CHECK_SEND_DONE;
        c->requests++;
    }

    return;

check_send_fail:
    ngx_http_gslb_check_status_update(peer,0);
    ngx_http_gslb_check_clean_event(peer);
}


static void
ngx_http_gslb_check_recv_handler(ngx_event_t *event)
{
    u_char                         *new_buf;
    ssize_t                         size, n;
    ngx_int_t                       rc;
    ngx_connection_t               *c;
    ngx_http_gslb_check_ctx_t  *ctx;
    ngx_http_gslb_check_peer_t *peer;

    if (ngx_http_gslb_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    if (peer->state != NGX_HTTP_CHECK_SEND_DONE) {

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto check_recv_fail;
        }

        return;
    }

    ctx = peer->check_data;

    if (ctx->recv.start == NULL) {
        /* 1/2 of the page_size, is it enough? */
        ctx->recv.start = ngx_palloc(c->pool, 10 * ngx_pagesize);
        if (ctx->recv.start == NULL) {
            goto check_recv_fail;
        }

        ctx->recv.last = ctx->recv.pos = ctx->recv.start;
        ctx->recv.end = ctx->recv.start + 10 * ngx_pagesize;
    }

    while (1) {
        n = ctx->recv.end - ctx->recv.last;

        /* buffer not big enough? enlarge it by twice */
        if (n == 0) {
            size = ctx->recv.end - ctx->recv.start;
            new_buf = ngx_palloc(c->pool, size * 2);
            if (new_buf == NULL) {
                goto check_recv_fail;
            }

            ngx_memcpy(new_buf, ctx->recv.start, size);

            ctx->recv.pos = ctx->recv.start = new_buf;
            ctx->recv.last = new_buf + size;
            ctx->recv.end = new_buf + size * 2;

            n = ctx->recv.end - ctx->recv.last;
        }

        size = c->recv(c, ctx->recv.last, n);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "http check recv size: %z, peer: %V ",
                       size, &peer->peer_addr->name);
        }
#endif

        if (size > 0) {
            ctx->recv.last += size;
            continue;
        } else if (size == 0 || size == NGX_AGAIN) {
            break;
        } else {
            c->error = 1;
            goto check_recv_fail;
        }
    }

    rc = peer->parse(peer);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http check parse rc: %i, peer: %V ",
                   rc, &peer->peer_addr->name);

    switch (rc) {

    case NGX_AGAIN:
        /* The peer has closed its half side of the connection. */
        if (size == 0) {
            ngx_http_gslb_check_status_update(peer,0);
            c->error = 1;
            break;
        }

        return;

    case NGX_ERROR:
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "check protocol %V error with peer: %V ",
                      &peer->conf->check_type_conf->name,
                      &peer->peer_addr->name);

        ngx_http_gslb_check_status_update(peer,0);
        break;

    case NGX_OK:
        /* fall through */

    default:
        ngx_http_gslb_check_status_update(peer,1);
        break;
    }

    peer->state = NGX_HTTP_CHECK_RECV_DONE;
    ngx_http_gslb_check_clean_event(peer);
    return;

check_recv_fail:
    ngx_http_gslb_check_status_update(peer,0);
    ngx_http_gslb_check_clean_event(peer);
}


static ngx_int_t
ngx_http_gslb_check_http_init(ngx_http_gslb_check_peer_t *peer)
{
    ngx_http_gslb_check_ctx_t       *ctx;
    ngx_http_gslb_check_srv_conf_t  *gcscf;

    ctx = peer->check_data;
    gcscf = peer->conf;

    ctx->send.start = ctx->send.pos = (u_char *)gcscf->send.data;
    ctx->send.end = ctx->send.last = ctx->send.start + gcscf->send.len;

    ctx->recv.start = ctx->recv.pos = NULL;
    ctx->recv.end = ctx->recv.last = NULL;

    ctx->state = 0;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));

    return NGX_OK;
}


static ngx_int_t
ngx_http_gslb_check_http_parse(ngx_http_gslb_check_peer_t *peer)
{
    ngx_int_t                       rc;
	u_char							*pcl,*pr, *end, *ps, *pe, *pm;
	ngx_int_t						ip_addr;
    ngx_http_gslb_check_ctx_t       *ctx;
    ngx_http_gslb_check_srv_conf_t  *gcscf;
	ngx_http_gslb_bad_peer_t *tmp;
	//ngx_queue_t				*busy;
	//ngx_queue_t				*idle;

    gcscf = peer->conf;
    ctx = peer->check_data;

    while((ctx->recv.last - ctx->recv.pos) > 0) 
	{
		if(ctx->parse_state == 0) {
        	rc = ngx_http_gslb_check_parse_status_line(ctx, &ctx->recv, &ctx->status);
			if (rc == NGX_AGAIN) {
				return rc;
			}

			if (rc == NGX_ERROR) {
				return rc;
			}

			if(ctx->status.code == 200) {
				ctx->parse_state = NGX_PARSE_STATUS_LINE_DONE;
			} else if (ctx->status.code == 304){
				return NGX_OK;
			}
		} else if(ctx->parse_state == NGX_PARSE_STATUS_LINE_DONE) {
			end = ngx_strnstr(ctx->recv.pos, "\r\n\r\n", ctx->recv.last - ctx->recv.pos);
			if(end) {
				ctx->parse_state = NGX_PARSE_HTTP_HEADER_DONE;
				pcl = ngx_strnstr(ctx->recv.pos, "Content-Length:",ctx->recv.last-ctx->recv.pos);
				if(pcl) {
					pcl = pcl + 15;
					while(*pcl && isspace(*pcl)) pcl ++;
					pr = pcl;
					while(*pr && !isspace(*pr)) pr ++;
					ctx->content_len = ngx_atoi(pcl, pr-pcl);
					if(ctx->content_len == NGX_ERROR) {
						return NGX_ERROR;
					}
				} else {
					return NGX_ERROR;
				}

				ctx->recv.pos = end + 4;

			} else { ///\r\n\r\n not found
				return NGX_AGAIN;
			}

		} else if(ctx->parse_state == NGX_PARSE_HTTP_HEADER_DONE) {
			if(ctx->recv.last - ctx->recv.pos != ctx->content_len) {
				return NGX_AGAIN;
			} else { // data
				ngx_shmtx_lock(&peer->shm->mutex);
				////
				ngx_queue_add(&peer->shm->idle, &peer->shm->busy);
				ngx_queue_init(&peer->shm->busy);
				///reinit 
				ngx_rbtree_init(peer->shm->down_peers, peer->shm->down_peers_sentinel, ngx_rbtree_insert_value);
				////
				//nnop011.tlgslb.com.	111.10.19.199	0	1001
				ps = ctx->recv.pos;
				while(ps < ctx->recv.last) {
					pe = ngx_strlchr(ps, ctx->recv.last, '\n');
					if(pe == NULL) break;

					while(*ps && isspace(*ps)) ps ++;
					///host
					while(*ps && !isspace(*ps)) ps ++;
					while(*ps && isspace(*ps)) ps ++;
					///ip
					pm = ps;
					while(*pm && !isspace(*pm)) pm ++;
					ip_addr = ngx_inet_addr(ps, pm-ps);
					if(ip_addr == INADDR_NONE) {
						ps = pe + 1;
						continue;
					}
					////
					tmp = ngx_http_gslb_get_idle_bad_peer(&peer->shm->busy, &peer->shm->idle);
					if(tmp == NULL) {
						ps = pe + 1;
						continue;
					}
					tmp->addr = ntohl(ip_addr);
					tmp->node.key = tmp->addr;
					ngx_rbtree_insert(peer->shm->down_peers, &tmp->node);
					ps = pe + 1;
				}
				ngx_shmtx_unlock(&peer->shm->mutex);

				return NGX_OK;
			}
		}
    }

    return NGX_AGAIN;
}

static ngx_http_gslb_bad_peer_t *ngx_http_gslb_get_idle_bad_peer(ngx_queue_t *busy, ngx_queue_t *idle)
{
	ngx_shm_zone_t                      *shm_zone;
	ngx_slab_pool_t                     *shpool;
	ngx_http_gslb_bad_peer_t			*tmp;
	ngx_queue_t						*tail;

	shm_zone = check_peers_ctx->shm_zone;
	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

	if(ngx_queue_empty(idle)) {
		tmp = ngx_slab_alloc(shpool, sizeof(ngx_http_gslb_bad_peer_t));
		if(tmp == NULL) {
			return NULL;
		}
	} else {
		tail = ngx_queue_last(idle);
		ngx_queue_remove(tail);
		tmp = ngx_queue_data(tail, ngx_http_gslb_bad_peer_t, q);
	}

	memset(tmp,0,sizeof(ngx_http_gslb_bad_peer_t));
	///add busy
	ngx_queue_insert_tail(busy, &tmp->q);

	return tmp;
}


static ngx_int_t
ngx_http_gslb_check_parse_status_line(ngx_http_gslb_check_ctx_t *ctx, ngx_buf_t *b, ngx_http_status_t *status)
{
    u_char ch, *p;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (ch != 'H') {
                return NGX_ERROR;
            }

            state = sw_H;
            break;

        case sw_H:
            if (ch != 'T') {
                return NGX_ERROR;
            }

            state = sw_HT;
            break;

        case sw_HT:
            if (ch != 'T') {
                return NGX_ERROR;
            }

            state = sw_HTT;
            break;

        case sw_HTT:
            if (ch != 'P') {
                return NGX_ERROR;
            }

            state = sw_HTTP;
            break;

        case sw_HTTP:
            if (ch != '/') {
                return NGX_ERROR;
            }

            state = sw_first_major_digit;
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            status->code = status->code * 10 + ch - '0';

            if (++status->count == 3) {
                state = sw_space_after_status;
                status->start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            status->end = p - 1;
            if (ch == LF) {
                goto done;
            } else {
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    if (status->end == NULL) {
        status->end = p;
    }

    ctx->state = sw_start;

    return NGX_OK;
}

static void
ngx_http_gslb_check_http_reinit(ngx_http_gslb_check_peer_t *peer)
{
    ngx_http_gslb_check_ctx_t  *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;

    ctx->state = 0;
    ctx->parse_state = 0;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));
}


static void
ngx_http_gslb_check_status_update(ngx_http_gslb_check_peer_t *peer, ngx_int_t result)
{
	
	if(result){
		peer->shm->failed = 0;
	}
	else{
		peer->shm->failed = 1;
	}
    peer->shm->access_time = ngx_current_msec;
}


static void
ngx_http_gslb_check_clean_event(ngx_http_gslb_check_peer_t *peer)
{
    ngx_connection_t                    *c;
    ngx_http_gslb_check_srv_conf_t  *gcscf;
    ngx_check_conf_t                    *cf;

    c = peer->pc.connection;
    gcscf = peer->conf;
    cf = gcscf->check_type_conf;

    if (c) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http check clean event: index:%i, fd: %d",
                       peer->index, c->fd);
        if (c->error == 0 &&
            cf->need_keepalive &&
            (c->requests < gcscf->check_keepalive_requests))
        {
            c->write->handler = ngx_http_gslb_check_dummy_handler;
            c->read->handler = ngx_http_gslb_check_discard_handler;
        } else {
            ngx_close_connection(c);
            peer->pc.connection = NULL;
        }
    }

    if (peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&peer->check_timeout_ev);
    }

    peer->state = NGX_HTTP_CHECK_ALL_DONE;

    if (peer->check_data != NULL && peer->reinit) {
        peer->reinit(peer);
    }

    peer->shm->owner = NGX_INVALID_PID;
}


static void
ngx_http_gslb_check_timeout_handler(ngx_event_t *event)
{
    ngx_http_gslb_check_peer_t  *peer;

    if (ngx_http_gslb_check_need_exit()) {
        return;
    }

    peer = event->data;
    peer->pc.connection->error = 1;

    ngx_log_error(NGX_LOG_ERR, event->log, 0,
                  "check time out with peer: %V ",
                  &peer->peer_addr->name);

    ngx_http_gslb_check_status_update(peer,0);
    ngx_http_gslb_check_clean_event(peer);
}


static void
ngx_http_gslb_check_finish_handler(ngx_event_t *event)
{
    if (ngx_http_gslb_check_need_exit()) {
        return;
    }
}


static ngx_int_t
ngx_http_gslb_check_need_exit()
{
    if (ngx_terminate || ngx_exiting || ngx_quit) {
        ngx_http_gslb_check_clear_all_events();
        return 1;
    }

    return 0;
}


static void
ngx_http_gslb_check_clear_all_events()
{
    ngx_uint_t                       i;
    ngx_connection_t                *c;
    ngx_http_gslb_check_peer_t  *peer;
    ngx_http_gslb_check_peers_t *peers;

    static ngx_flag_t                has_cleared = 0;

    if (has_cleared || check_peers_ctx == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "clear all the events on %P ", ngx_pid);

    has_cleared = 1;

    peers = check_peers_ctx;

    peer = peers->peers.elts;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (peer[i].check_ev.timer_set) {
            ngx_del_timer(&peer[i].check_ev);
        }

        if (peer[i].check_timeout_ev.timer_set) {
            ngx_del_timer(&peer[i].check_timeout_ev);
        }

        c = peer[i].pc.connection;
        if (c) {
            ngx_close_connection(c);
            peer[i].pc.connection = NULL;
        }

        if (peer[i].pool != NULL) {
            ngx_destroy_pool(peer[i].pool);
            peer[i].pool = NULL;
        }
    }
}

static ngx_check_conf_t *
ngx_http_get_check_type_conf(ngx_str_t *str)
{
    ngx_uint_t  i;

    for (i = 0; /* void */ ; i++) {

        if (ngx_check_types[i].type == 0) {
            break;
        }

        if (str->len != ngx_check_types[i].name.len) {
            continue;
        }

        if (ngx_strncmp(str->data, ngx_check_types[i].name.data,
                        str->len) == 0)
        {
            return &ngx_check_types[i];
        }
    }

    return NULL;
}


static char *
ngx_http_gslb_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                            *value, s;
	ngx_str_t							 host;
    ngx_uint_t                           i, port;
    ngx_msec_t                           interval, timeout;
    ngx_http_gslb_check_srv_conf_t  *gcscf = conf;

    /* default values */
    port = 0;
    interval = 3000;
    timeout = 1000;

    value = cf->args->elts;

    if (gcscf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {

		if(ngx_strncmp(value[i].data, "host=", 5) == 0) {
			host.data = value[i].data + 5;
			host.len = value[i].len - 5;
			if(ngx_http_gslb_check_add_peer(cf,&host) != NGX_OK) {
                goto invalid_check_parameter;
			}

			continue;
		}

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            gcscf->check_type_conf = ngx_http_get_check_type_conf(&s);

            if (gcscf->check_type_conf == NULL) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "port=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            port = ngx_atoi(s.data, s.len);
            if (port == (ngx_uint_t) NGX_ERROR || port == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            interval = ngx_atoi(s.data, s.len);
            if (interval == (ngx_msec_t) NGX_ERROR || interval == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = ngx_atoi(s.data, s.len);
            if (timeout == (ngx_msec_t) NGX_ERROR || timeout == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        goto invalid_check_parameter;
    }

    gcscf->port = port;
    gcscf->check_interval = interval;
    gcscf->check_timeout = timeout;

    if (gcscf->check_type_conf == NGX_CONF_UNSET_PTR) {
        ngx_str_set(&s, "http");
        gcscf->check_type_conf = ngx_http_get_check_type_conf(&s);
    }

    return NGX_CONF_OK;

invalid_check_parameter:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

static void *
ngx_http_gslb_check_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_gslb_check_main_conf_t  *gcmcf;

    gcmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gslb_check_main_conf_t));
    if (gcmcf == NULL) {
        return NULL;
    }

    gcmcf->peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_gslb_check_peers_t));
    if (gcmcf->peers == NULL) {
        return NULL;
    }

    gcmcf->peers->checksum = 0;

    if (ngx_array_init(&gcmcf->peers->peers, cf->pool, 16, sizeof(ngx_http_gslb_check_peer_t)) != NGX_OK)
    {
        return NULL;
    }

    return gcmcf;
}


static char *
ngx_http_gslb_check_init_main_conf(ngx_conf_t *cf, void *conf)
{
	/// shm
    return ngx_http_gslb_check_init_shm(cf, conf);
}


static void *
ngx_http_gslb_check_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_gslb_check_srv_conf_t  *gcscf;

    gcscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gslb_check_srv_conf_t));
    if (gcscf == NULL) {
        return NULL;
    }

    gcscf->port = NGX_CONF_UNSET_UINT;
    gcscf->check_timeout = NGX_CONF_UNSET_MSEC;
    gcscf->check_keepalive_requests = NGX_CONF_UNSET_UINT;
    gcscf->check_type_conf = NGX_CONF_UNSET_PTR;

    return gcscf;
}


static char *
ngx_http_gslb_check_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_str_t                            *shm_name;
    ngx_uint_t                            shm_size;
    ngx_shm_zone_t                       *shm_zone;
    ngx_http_gslb_check_main_conf_t  *gcmcf = conf;

    if (gcmcf->peers->peers.nelts > 0) {
        ngx_http_gslb_check_shm_generation++;

        shm_name = &gcmcf->peers->check_shm_name;

        ngx_http_gslb_check_get_shm_name(shm_name, cf->pool, ngx_http_gslb_check_shm_generation);

        /* The default check shared memory size is 1M */
        shm_size = 10 * 1024 * 1024;

        shm_size = shm_size < gcmcf->check_shm_size ? gcmcf->check_shm_size : shm_size;

        shm_zone = ngx_shared_memory_add(cf, shm_name, shm_size, &ngx_http_gslb_check_module);

        shm_zone->data = cf->pool;
        check_peers_ctx = gcmcf->peers;
		///
		check_peers_ctx->shm_zone = shm_zone;
		///

        shm_zone->init = ngx_http_gslb_check_init_shm_zone;

    } else {
         check_peers_ctx = NULL;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_gslb_check_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool, ngx_uint_t generation)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, SHM_NAME_LEN, "%s#%ui", "ngx_http_gslb_check", generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_gslb_check_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
	size_t                               size;
	ngx_str_t                            oshm_name;
	ngx_int_t                            rc;
	ngx_uint_t                           i, number;
	ngx_pool_t                          *pool;
	ngx_slab_pool_t                     *shpool;
	ngx_http_gslb_check_peer_t      *peer;
	ngx_http_gslb_check_peers_t     *peers;
	ngx_http_gslb_check_peer_shm_t  *peer_shm;
	ngx_http_gslb_check_peers_shm_t *peers_shm, *opeers_shm;

	opeers_shm = NULL;
	peers_shm = NULL;
	ngx_str_null(&oshm_name);

	peers = check_peers_ctx;
	if (peers == NULL) {
		return NGX_OK;
	}

	number = peers->peers.nelts;
	if (number == 0) {
		return NGX_OK;
	}

	pool = shm_zone->data;
	if (pool == NULL) {
		pool = ngx_cycle->pool;
	}

	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

	size = sizeof(*peers_shm) + (number - 1) * sizeof(ngx_http_gslb_check_peer_shm_t);

	peers_shm = ngx_slab_alloc(shpool, size);

	if (peers_shm == NULL) {
		goto failure;
	}

	ngx_memzero(peers_shm, size);

	peers_shm->generation = ngx_http_gslb_check_shm_generation;
	peers_shm->checksum = peers->checksum;
	peers_shm->number = number;

	peer = peers->peers.elts;

	for (i = 0; i < number; i++) {

		peer_shm = &peers_shm->peers[i];

		peer_shm->owner = NGX_INVALID_PID;

		peer_shm->socklen = peer[i].peer_addr->socklen;
		peer_shm->sockaddr = ngx_slab_alloc(shpool, peer_shm->socklen);
		if (peer_shm->sockaddr == NULL) {
			goto failure;
		}

		ngx_memcpy(peer_shm->sockaddr, peer[i].peer_addr->sockaddr, peer_shm->socklen);

		rc = ngx_http_gslb_check_init_shm_peer(peer_shm, NULL, shpool, pool, &peer[i].peer_addr->name);
		if (rc != NGX_OK) {
			return NGX_ERROR;
		}
	}

	peers->peers_shm = peers_shm;
	shm_zone->data = peers_shm;

	return NGX_OK;

failure:
	ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
			"http gslb check_shm_size is too small, "
			"you should specify a larger size.");
	return NGX_ERROR;
}


static ngx_int_t
ngx_http_gslb_check_init_shm_peer(ngx_http_gslb_check_peer_shm_t *psh, ngx_http_gslb_check_peer_shm_t *opsh,ngx_slab_pool_t *shpool, ngx_pool_t *pool, ngx_str_t *name)
{
    u_char  *file;

    if (opsh) {

        psh->access_time  = opsh->access_time;
		psh->down_peers = opsh->down_peers;
		psh->down_peers_sentinel = opsh->down_peers_sentinel;
		psh->busy = opsh->busy;
		psh->idle = opsh->idle;

    } else {
        psh->access_time  = 0;
		psh->failed = 0;
        psh->down_peers = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
		if(psh->down_peers == NULL) {
			return NGX_ERROR;
		}
		psh->down_peers_sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
		if(psh->down_peers_sentinel == NULL) {
			return NGX_ERROR;
		}
		ngx_rbtree_init(psh->down_peers, psh->down_peers_sentinel, ngx_rbtree_insert_value);

		ngx_queue_init(&psh->busy);
		ngx_queue_init(&psh->idle);
    }

#if (NGX_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    file = ngx_pnalloc(pool, ngx_cycle->lock_file.len + name->len);
    if (file == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_sprintf(file, "%V%V%Z", &ngx_cycle->lock_file, name);

#endif

    if (ngx_shmtx_create(&psh->mutex, &psh->lock, file) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_gslb_check_init_process(ngx_cycle_t *cycle)
{
    return ngx_http_gslb_check_add_timers(cycle);
}

static ngx_http_gslb_bad_peer_t * ngx_http_gslb_lookup_bad_peer(ngx_rbtree_t *tree, in_addr_t addr)
{
	ngx_rbtree_node_t *node, *sentinel;

	node = tree->root;
	sentinel = tree->sentinel;

	while(node != sentinel) {

		if(addr < node->key) {
			node = node->left;
			continue;
		}

		if(addr > node->key) {
			node = node->right;
			continue;
		}

		return (ngx_http_gslb_bad_peer_t*) node;
	}

	return NULL;
}

