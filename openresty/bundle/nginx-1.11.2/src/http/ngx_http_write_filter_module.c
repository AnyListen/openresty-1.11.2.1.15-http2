
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <dlfcn.h>
#include <net/if.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

//add by zdw

#include "/usr/local/bandwidth/include/bandwidth_header.h"

typedef struct {
	char	loc_ip[64];
	pid_t	pid;
}ngx_bw_t;

typedef struct  {
	ngx_flag_t	enable;
}ngx_http_write_filter_loc_conf_t;

typedef struct {
	ngx_flag_t band_width_enable;
}ngx_http_write_filter_main_conf_t;

static ngx_bw_t *bw = NULL;

static u_char * ngx_inet_get_local_addr();
static ngx_int_t ngx_http_write_init_process(ngx_cycle_t *cycle);
static void* ngx_http_write_filter_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_write_filter_init_main_conf(ngx_conf_t *cf, void *conf);
static void ngx_http_write_exit_process(ngx_cycle_t *cycle);

static void * ngx_http_write_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_write_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

///

static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_write_filter_commands[] = {

	{ ngx_string("one_minute"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_write_filter_loc_conf_t, enable),
		NULL },
	{ ngx_string("band_width_open"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_write_filter_main_conf_t, band_width_enable),
		NULL },

	ngx_null_command
};


static ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_write_filter_init,            /* postconfiguration */

    ngx_http_write_filter_create_main_conf,                                  /* create main configuration */
    ngx_http_write_filter_init_main_conf,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_write_create_loc_conf,       /* create location configuration */
    ngx_http_write_merge_loc_conf,        /* merge location configuration */
};


ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_write_filter_module_ctx,     /* module context */
    ngx_http_write_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_write_init_process,     	   /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_write_exit_process,           /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_write_filter_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_write_filter_main_conf_t  *wfmcf;

    wfmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_write_filter_main_conf_t));
    if (wfmcf == NULL) {
        return NULL;
    }
    wfmcf->band_width_enable = NGX_CONF_UNSET;
    return wfmcf;
}

static char *
ngx_http_write_filter_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_write_filter_main_conf_t *wfmcf = conf;

    if (wfmcf->band_width_enable == NGX_CONF_UNSET) {
        wfmcf->band_width_enable = 0;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	//
	ngx_str_t bw_buf;
	size_t	bw_size;
	off_t	sent_band;
	//
    off_t                      size, sent, nsent, limit, last_sent;
    ngx_uint_t                 last, flush, sync;
    ngx_msec_t                 delay;
	///add by zdw
    ngx_msec_t			msec;
	ngx_time_t			*tp;
    //
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
	ngx_http_write_filter_main_conf_t  *wfmcf;

	//
	ngx_http_write_filter_loc_conf_t  *conf = ngx_http_get_module_loc_conf(r, ngx_http_write_filter_module);
	wfmcf = ngx_http_get_module_main_conf(r, ngx_http_write_filter_module);
	//

    c = r->connection;

    if (c->error) {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &r->out;
    sent_band = c->sent;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return NGX_OK;
    }

    if (c->write->delayed) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    if (size == 0
        && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush || sync) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }
	
    tp = ngx_timeofday();
	msec = tp->sec*1000 + tp->msec;
	
    if (r->limit_rate) {
        if (r->limit_rate_after == 0) {
            r->limit_rate_after = clcf->limit_rate_after;
        }

		///add by zdw
	    if(clcf->limit_rate_interval) {

		    if(c->sent - (off_t)r->limit_rate_after >= 0) {

			    limit = clcf->limit_rate_interval * r->limit_rate - (c->sent - r->limit_sent);
			    if(limit <= 0 ) {

					c->write->delayed = 1;
					delay = (ngx_msec_t) (clcf->limit_rate_interval * 1000 - 
							(msec - r->limit_msec) + 1);
					ngx_add_timer(c->write, delay);
					c->buffered |= NGX_HTTP_WRITE_BUFFERED;

					r->limit_sent = c->sent;
					r->limit_msec = msec+delay;
					return NGX_AGAIN;
			    }

				if(msec - r->limit_msec >= clcf->limit_rate_interval * 1000) {
						r->limit_sent = c->sent;
						r->limit_msec = msec;
				}
			} else {
				limit = (off_t) r->limit_rate * (ngx_time() - r->start_sec + 1)
					- (c->sent - r->limit_rate_after);

				r->limit_sent = c->sent;
				r->limit_msec = msec;
			}
		}else {
			limit = (off_t) r->limit_rate * (ngx_time() - r->start_sec + 1)
				- (c->sent - r->limit_rate_after);

			if (limit <= 0) {
				c->write->delayed = 1;
				delay = (ngx_msec_t) (- limit * 1000 / r->limit_rate + 1);
				ngx_add_timer(c->write, delay);

				c->buffered |= NGX_HTTP_WRITE_BUFFERED;

				return NGX_AGAIN;
			}
		}

        if (clcf->sendfile_max_chunk
            && (off_t) clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }

    } else {
        limit = clcf->sendfile_max_chunk;
    }
	
	sent = c->sent;
	last_sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    chain = c->send_chain(c, r->out, limit);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

	
	if(!wfmcf->band_width_enable || !conf->enable) {
		goto NEXT;
	}

	// add by zdw
	ngx_uint_t	i, ck_len, key;
	int hit;
	ngx_buf_t		*b;
	char *host, *client_ip, *uri, *cookie;
	ngx_table_elt_t **ck;
	ngx_http_variable_value_t *v;
	ngx_time_t	*tmp;
	ngx_msec_t  cur_msec;
	u_char		*last_str, *and_mark, *sdt_str, *ques_mark;

	bw_size = c->sent - last_sent;

	if( bw_size && !r->dnion_request) {
		bw_buf.len = r->headers_in.server.len + 1  //domain
			+ r->connection->addr_text.len + 1    //client ip
		    + r->unparsed_uri.len + 1;  //uri

		//hls request must get sdtfrom form vkey
		if(r->hls_request && r->sdtfrom.len != 0){
			if((r->sdtfrom.len != 1 || r->sdtfrom.data[0] != '0')){	//sdtfrom=0 
				bw_buf.len += r->sdtfrom.len;
				bw_buf.len += 1;				//1 is for "?" or "&"
			}
		}

		ck_len = 0;
		ck = r->headers_in.cookies.elts;
		for(i = 0; i < r->headers_in.cookies.nelts; i++) {
			ck_len += ck[i]->key.len;
			ck_len += 1; 
			ck_len += ck[i]->value.len;
			ck_len += 1; 
		}

		bw_buf.len += ck_len;

		b = ngx_create_temp_buf(r->pool, bw_buf.len);
		if(b == NULL) {
			goto  NEXT;
		}

		///
		host = (char *)b->last;
		b->last = ngx_copy(b->last, r->headers_in.server.data, r->headers_in.server.len);
		*b->last = '\0';
		b->last ++;
		
		///
		client_ip = (char *)b->last;
		b->last = ngx_copy(b->last, r->connection->addr_text.data, r->connection->addr_text.len);
		*b->last = '\0';
		b->last ++;

		///
		if(!r->hls_request || (r->hls_request && r->sdtfrom.len == 0) 
					||(r->hls_request && r->sdtfrom.len == 1 && r->sdtfrom.data[0] == '0')) {
			uri = (char *)b->last;
			b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);
			*b->last = '\0';
			b->last ++;
		}
		else {
			uri = (char *)b->last;
			b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

			if(( ques_mark = ngx_strlchr((u_char *)uri, b->last, '?')) == NULL){
				*b->last++ = '?';
				b->last = ngx_copy(b->last, "sdtfrom=", ngx_strlen("sdtfrom="));
				b->last = ngx_copy(b->last, r->sdtfrom.data, r->sdtfrom.len);
				*b->last++ = '\0';
			}
			else {
				if((sdt_str=ngx_strnstr(ques_mark, (char *)"?sdtfrom=", b->last - ques_mark)) != NULL) {
					if ( (and_mark = ngx_strlchr(sdt_str, b->last,'&')) == NULL ){
						//uri?sdtfrom=xxxx    ----->  uri?            (sdtfrom=xxxx is clear)
						ngx_memzero(sdt_str + 1, b->last - (sdt_str + 1));
						b->last = sdt_str + 1;
					}
					else{
						//uri?sdtfrom=xxxx&a=1 -----> uri?a=1& 

						last_str = ngx_copy(sdt_str + 1, and_mark + 1, b->last - (and_mark + 1 ));
						ngx_memzero(last_str, b->last - last_str);
						b->last = last_str;
						*b->last++ = '&';
					}
				}
				else if((sdt_str=ngx_strnstr(ques_mark, (char *)"&sdtfrom=", b->last - ques_mark)) != NULL) {
					if ( (and_mark = ngx_strlchr(sdt_str + 1, b->last,'&')) == NULL ){
						//uri?a=1&sdtfrom=xxxx	-----> uri?a=1&		(sdtfrom=xxxx is clear)
						ngx_memzero(sdt_str + 1, b->last - (sdt_str + 1));
						b->last = sdt_str + 1;
					}
					else {
						//uri?a=1&sdtfrom=xxxx&b=2 ----> uri?a=1&b=2&
						last_str = ngx_copy(sdt_str, and_mark, b->last - and_mark);
						ngx_memzero(last_str, b->last - last_str);
						b->last = last_str;
						*b->last++ = '&';
					}
				}
				else{
					if( b->last[-1] != '?' ){
						*b->last++ = '&';
					}
				}

				b->last = ngx_copy(b->last, "sdtfrom=", ngx_strlen("sdtfrom="));
				b->last = ngx_copy(b->last, r->sdtfrom.data, r->sdtfrom.len);
				*b->last++ = '\0';
			}
		}

		///
		cookie = NULL;
		if( ck_len) {
			cookie = (char *)b->last;
			ck = r->headers_in.cookies.elts;
			for(i = 0; i < r->headers_in.cookies.nelts; i++) {
				b->last = ngx_copy(b->last, ck[i]->value.data, ck[i]->value.len);
				b->last = ngx_copy(b->last, ";", 1);
			}

			b->last[-1] = '\0';
		}

		static ngx_str_t crc = ngx_string("upstream_http_hittype");
		hit = 0;
		key = ngx_hash_key_lc(crc.data, crc.len);
		v = ngx_http_get_variable(r, &crc, key);
		if(v != NULL) {
			if(!v->not_found) {
				if(ngx_strlcasestrn(v->data, v->data + v->len, (u_char *) "hit", 3 - 1) != NULL) {
					hit = 1;
				}
			}
		}

		tmp = ngx_timeofday();
		cur_msec = tmp->msec;
		BandWidthInput(bw->pid, host, client_ip, bw->loc_ip, uri, ck_len?cookie:"-", "-", hit, bw_size, sent_band==0?1:0, r->bw_msec==0?cur_msec - r->start_msec: cur_msec-r->bw_msec);
                r->bw_msec = cur_msec;
	}

NEXT:
	//

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }
	
    if (ngx_http_top_write_filter){
        ngx_http_top_write_filter(r, sent);
    }
	
    if (r->limit_rate) {
       if(clcf->limit_rate_interval == 0) {
        nsent = c->sent;

        if (r->limit_rate_after) {

            sent -= r->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        delay = (ngx_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
	   }
    }

    if (limit
        && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * ngx_pagesize))
    {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
    }

    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    r->out = chain;

    if (chain) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_write_filter_init(ngx_conf_t *cf)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}

// add by zdw

static u_char * ngx_inet_get_local_addr()
{
    static  u_char      addr[32] = {'\0'};
    if(addr[0] != '\0'){
        return addr;
    }

    int                 fdnum, ifnum;
    struct ifconf       conf;
    struct ifreq       *ifr;
    char                buff[BUFSIZ];
    int                 count, check_flag;
    fdnum = socket(PF_INET, SOCK_DGRAM, 0);
    conf.ifc_len = BUFSIZ;
    conf.ifc_buf = buff;

    ioctl(fdnum, SIOCGIFCONF, &conf);
    ifnum = conf.ifc_len / sizeof(struct ifreq);
    ifr = conf.ifc_req;

    for (count = 0; count < ifnum; count++) {
        struct sockaddr_in *sin = (struct sockaddr_in *)(&ifr->ifr_addr);
        ioctl(fdnum, SIOCGIFFLAGS, ifr);
        check_flag = ifr->ifr_flags & IFF_LOOPBACK; 
        if ((check_flag == 0) && (ifr->ifr_flags && IFF_UP)) {
            char * paddr = inet_ntoa(sin->sin_addr);
            if(NULL == paddr){
                continue;
            }
            if(strlen(paddr) >= sizeof(addr)){
                continue;
            }
            strcpy((char *)addr,paddr);
            break;
        }
        ifr++;
    }
    close(fdnum);
    return addr;
}

static void *
ngx_http_write_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_write_filter_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_write_filter_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;

	return conf;
}

static char*
ngx_http_write_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_write_filter_loc_conf_t  *prev = parent;
	ngx_http_write_filter_loc_conf_t  *conf = child;
	ngx_conf_merge_value(conf->enable, prev->enable, 1);

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_write_init_process(ngx_cycle_t *cycle)
{
	u_char *ip;
	ngx_http_write_filter_main_conf_t  *wfmcf;
	bw = ngx_pcalloc(cycle->pool, sizeof(ngx_bw_t));
	if(bw == NULL) {
		return NGX_ERROR;
	}

        bw->pid = ngx_pid;

	ip = ngx_inet_get_local_addr();
	if(ngx_strlen(ip) >= sizeof(bw->loc_ip)){
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "local ip length is too long");
		return NGX_ERROR;
	}
	strcpy(bw->loc_ip,(const char *)ip);
	
	wfmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_write_filter_module);
	if(wfmcf->band_width_enable) {
		if(BandWidthInit() != 0) {
			ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "bandwidthInit fail");
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static void ngx_http_write_exit_process(ngx_cycle_t *cycle)
{
	ngx_http_write_filter_main_conf_t  *wfmcf;
	wfmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_write_filter_module);
	if(wfmcf->band_width_enable) {
		BandWidthFree();
	}
}

