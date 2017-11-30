#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_rbtree_node_t	node;
	ngx_msec_t			last;
	ngx_msec_t			forbid_time;
	ngx_msec_t			forbid_flag;
	u_short				len;
	ngx_uint_t			count;
	ngx_queue_t			nq;
	u_char				name[255];
} ngx_http_limit_req_number_node_t;

typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;
} ngx_http_limit_req_number_shctx_t;

typedef struct {
    uint32_t  left;
    uint32_t  right;
} ngx_http_ip_block_t;

typedef struct {
    ngx_http_limit_req_number_shctx_t  *sh;
    ngx_slab_pool_t             *shpool;
    ngx_uint_t                   rate;
	ngx_uint_t                   interval;
	ngx_uint_t					 interval_forbid;
	ngx_array_t                 *wlist;		/* array of ngx_http_ip_block_t */
	ngx_flag_t					 bwlimit;	/* bandwidth limit on/off */
    ngx_int_t                    index;
    ngx_str_t                    var;
} ngx_http_limit_req_number_ctx_t;

typedef struct {
	ngx_shm_zone_t	*shm_zone;
}ngx_http_limit_req_number_conf_t;

static ngx_int_t ngx_http_limit_req_number_handler(ngx_http_request_t *r);
static void *ngx_http_limit_req_number_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_req_number_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_limit_req_number_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf); 
static char *ngx_http_limit_req_number(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_limit_req_number_init(ngx_conf_t *cf);
static ngx_http_limit_req_number_node_t *ngx_http_limit_req_number_lookup(ngx_rbtree_t *tree, u_char *name, size_t size, uint32_t hash);
static ngx_int_t ngx_http_limit_req_number_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static void ngx_http_limit_req_number_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

extern void * ngx_http_bandwidth_limit_lookup(void *conf, ngx_uint_t hash, ngx_str_t *key);

#define SKIPSPACE(s,e)						\
{											\
	while ((' ' == *s) || ('\t' == *s)) {	\
		if (s >= e) {						\
			break;							\
		}									\
		s++;								\
	}										\
}

#define GETSPACE(s,e)						\
{											\
	while ((' ' != *s) && ('\t' != *s)) {	\
		if (s >= e) {						\
			break;							\
		}									\
		s++;								\
	}										\
}

static ngx_command_t  ngx_http_limit_req_number_commands[] = {

	{ ngx_string("limit_req_number_zone"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE4|NGX_CONF_TAKE5,
	  ngx_http_limit_req_number_zone,
	  0,
	  0,
	  NULL },

	{ ngx_string("limit_req_number"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_http_limit_req_number,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

	ngx_null_command
};

static ngx_http_module_t  ngx_http_limit_req_number_module_ctx = {
	NULL,									/* preconfiguration */
	ngx_http_limit_req_number_init,			/* postconfiguration */

	NULL,									/* create main configuration */
	NULL,									/* init main configuration */
	
	NULL,									/* create server configuration */
	NULL,									/* merge server configuration */

	ngx_http_limit_req_number_create_conf,	/* create location configuration */
	ngx_http_limit_req_number_merge_conf	/* merge location configuration */
};

ngx_module_t  ngx_http_limit_req_number_module = {
	NGX_MODULE_V1,
	&ngx_http_limit_req_number_module_ctx,		/* module context */
	ngx_http_limit_req_number_commands,			/* module directives */
	NGX_HTTP_MODULE,							/* module type */
	NULL,										/* init master */
	NULL,										/* init module */
	NULL,										/* init process */
	NULL,										/* init thread */
	NULL,										/* exit thread */
	NULL,										/* exit process */
	NULL,										/* exit master */
	NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_limit_req_number_handler(ngx_http_request_t *r)
{
	uint32_t                   hash;
	size_t                     len,i;
	ngx_str_t                  req_ip;
	ngx_time_t                 *tp;
	ngx_msec_t                 now,ms,ms_forbid;
	ngx_queue_t					*q;
	in_addr_t                   ipaddr;
	ngx_http_ip_block_t			*ipblk;
	ngx_array_t					*wlary;
	ngx_http_variable_value_t   *vv;
	ngx_http_limit_req_number_ctx_t    *ctx;
	ngx_http_limit_req_number_conf_t   *lrcf;
	ngx_http_limit_req_number_node_t	*node;

	tp = ngx_timeofday();
	now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

	lrcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_number_module);

	if(lrcf->shm_zone == NGX_CONF_UNSET_PTR)
	{
		return NGX_DECLINED;
	}

	ctx = lrcf->shm_zone->data;

	vv = ngx_http_get_indexed_variable(r, ctx->index);

	if (vv == NULL || vv->not_found) {
		return NGX_DECLINED;
	}

	len = vv->len;

	if(len == 0) {
		return NGX_DECLINED;
	}

	if(len > 255) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"the value of the \"%V\" variable "
					"is more than 255 bytes: \"%v\"",
					&ctx->var, vv);
		return NGX_DECLINED;
	}

	/* 
	 * add feature: limit request by total bandwidth 
	 */
	/*if (ctx->bwlimit == 1) {
		if (ngx_http_bandwidth_limit_lookup_alarm(r) == 0) {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
										"trigger limite req rule but not reach bandwidth limit.");
			return NGX_DECLINED;
		}
	}*/
	
	/* only handle whitelist for client remote addr */
	if (!ngx_strncmp(ctx->var.data, "binary_remote_addr", ctx->var.len)) {

		wlary = ctx->wlist;
		req_ip = r->connection->addr_text;

		if (wlary != NULL) {
			ipblk = wlary->elts;

			for (i = 0;i < wlary->nelts; i++) {
				
				ipaddr = ngx_inet_addr(req_ip.data, req_ip.len);
				if (ipaddr == INADDR_NONE) {
			        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
										"ngx_inet_addr client ip failed: \"%V\"", &req_ip);
					return NGX_DECLINED;
			    }				
				ipaddr = ntohl(ipaddr);				
				
				if (ipblk[i].left <= ipaddr && ipblk[i].right >= ipaddr) {
					ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
										"whitelist skip: ip \"%V\" left:%lu,right:%lu, ipaddr:%lu",
										&req_ip,ipblk[i].left, ipblk[i].right,ipaddr);
					return NGX_DECLINED;
				}
			}
		}
	}
	

	hash = ngx_crc32_short(vv->data, len);

	ngx_shmtx_lock(&ctx->shpool->mutex);

	node = ngx_http_limit_req_number_lookup(&ctx->sh->rbtree,vv->data,len,hash);

	//not found 
	if(node == NULL) {
		node = ngx_slab_alloc_locked(ctx->shpool, sizeof(ngx_http_limit_req_number_node_t));

		//delete the oldest by force
		if(node == NULL){

			if (ngx_queue_empty(&ctx->sh->queue)) {
				ngx_shmtx_unlock(&ctx->shpool->mutex);
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

		
			q = ngx_queue_last(&ctx->sh->queue);

			node = ngx_queue_data(q, ngx_http_limit_req_number_node_t, nq);
			
			ngx_rbtree_delete(&ctx->sh->rbtree, &node->node);

			ngx_queue_remove(q);
			
		}

		node->node.key = hash;
		node->len = len; 
		node->count = 1; 
		node->last = now;
		node->forbid_time = now;
		node->forbid_flag = 0;
		ngx_memzero(node->name,sizeof(node->name));
		ngx_memcpy(node->name, vv->data, len);

		ngx_rbtree_insert(&ctx->sh->rbtree, &node->node);
		ngx_queue_insert_head(&ctx->sh->queue, &node->nq);
	}
	//find
	else {

		ms = (ngx_msec_t) (now - node->last);
		ms_forbid = (ngx_msec_t) (now - node->forbid_time);

		//status:forbidden
		if(node->forbid_flag == 1) {
			if(ms_forbid > ctx->interval_forbid * 1000) {
				node->forbid_flag = 0;
				node->last = now;
				node->count = 1;
			} else {
				ngx_queue_remove(&node->nq);
				ngx_queue_insert_head(&ctx->sh->queue, &node->nq);
				ngx_shmtx_unlock(&ctx->shpool->mutex);
				return NGX_HTTP_FORBIDDEN;
			}
		}
		//status:not forbidden
		else {
			
			//20r/5m:not excess 5m
			if(ms <= ctx->interval * 1000) {
				node->count++;
			}
			//20r/5m:excess 5m
			else {
				node->last = now;
				node->count = 1;
			}
		}

		ngx_queue_remove(&node->nq);
		ngx_queue_insert_head(&ctx->sh->queue, &node->nq);

		if(node->count > ctx->rate) {
			node->forbid_flag = 1;
			node->forbid_time = now;
			ngx_shmtx_unlock(&ctx->shpool->mutex);
			return NGX_HTTP_FORBIDDEN;
		} else {
			ngx_shmtx_unlock(&ctx->shpool->mutex);
			return NGX_DECLINED;
		}
	}

	ngx_shmtx_unlock(&ctx->shpool->mutex);
	return NGX_DECLINED;
}

static void *
ngx_http_limit_req_number_create_conf(ngx_conf_t *cf)
{
	ngx_http_limit_req_number_conf_t *conf;

	conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_limit_req_number_conf_t));
	if(conf == NULL) {
		return NULL;
	}

	conf->shm_zone = NGX_CONF_UNSET_PTR;

	return conf;
}

static char *
ngx_http_limit_req_number_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	return NGX_OK;
}

static char *
ngx_http_limit_req_number_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_flag_t				   fbwlimit;
	u_char                    *p,*p1,*last,*base;
    size_t                     scale_len,rate_len,fsize;
    ssize_t                    size,n;
	in_addr_t                  start, end;
	ngx_array_t               *wlist;
    ngx_str_t                 *value, name, s, forbidden_time;
    ngx_int_t                  rate, scale,forbid;
    ngx_uint_t                 i;
	ngx_file_t                 file;
	ngx_file_info_t            fi;
    ngx_shm_zone_t            *shm_zone;
	ngx_http_ip_block_t       *ewl;
	
    ngx_http_limit_req_number_ctx_t  *ctx;
	

	value = cf->args->elts;

	ctx = NULL;
	size = 0;
    rate = 1;
    scale = 1;
    name.len = 0;
	scale_len = 0;
	rate_len = 0;
	forbid = 0;
	fbwlimit = 0;

	/* initialize whitelist array */
	wlist = ngx_array_create(cf->pool, 8, sizeof(ngx_http_ip_block_t));
	if (wlist == NULL) {
		return NGX_CONF_ERROR;
	}

	for (i = 1; i < cf->args->nelts; i++) {

		if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
		
			name.data = value[i].data + 5;

			p = (u_char *) ngx_strchr(name.data, ':');

			if (p == NULL) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			name.len = p - name.data;

			s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

			size = ngx_parse_size(&s);

			if (size == NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (size < (ssize_t) (8 * ngx_pagesize)) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"zone \"%V\" is too small", &value[i]);
				return NGX_CONF_ERROR;
			}
	
			continue;
		}

		if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

			last = value[i].data + value[i].len;

			p = (u_char *)ngx_strstr(value[i].data,"r/");
			if(p == NULL){
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"rate \"%V\" is invalid", &value[i]);
				return NGX_CONF_ERROR;
			}

			p1 =  p + 2;
			scale_len = (last - 1) - p1;

			if(scale_len == 0) {
				scale = 1;
			}
			else {
				scale = ngx_atoi(p1, scale_len);
				if( scale <= NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
										"rate \"%V\" is invalid", &value[i]);
					return NGX_CONF_ERROR;
				}
			}

			if(value[i].data[value[i].len-1] == 's') {
				scale *= 1;
			} else if(value[i].data[value[i].len-1] == 'm') {
				scale *= 60;
			} else if(value[i].data[value[i].len-1] == 'h') {
				scale *= (60 * 60);
			} else if(value[i].data[value[i].len-1] == 'd') {
				scale *= (24 * 60 * 60);
			} else if(value[i].data[value[i].len-1] == 'w') {
				scale *= (7 * 24 * 60 * 60);
			} else if(value[i].data[value[i].len-1] == 'M') {
				scale *= (30 * 24 * 60 * 60);
			} else {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
									"rate \"%V\" is invalid", &value[i]);
				return NGX_CONF_ERROR;
			}
			
			rate_len = p - value[i].data - 5;
			rate = ngx_atoi(value[i].data + 5, rate_len);
			if (rate <= NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "rate \"%V\" is invalid", &value[i]);
				return NGX_CONF_ERROR;
			}

			continue;

		}

		if (ngx_strncmp(value[i].data, "forbidden_time=", 15) == 0) {
			
				forbidden_time.data = value[i].data + 15;
				forbidden_time.len = value[i].len - 15;
	
				forbid = ngx_parse_time(&forbidden_time,1);

				continue;
		}

		if (ngx_strncmp(value[i].data, "bwlimit=", 8) == 0) {
	
				if (ngx_strncmp(value[i].data + 8, "on", 2) == 0) {
					fbwlimit = 1;
				}

				continue;
		}

		/* add whitelist for client ip or server ip at 2016/10/18 */
		
		if (ngx_strncmp(value[i].data, "wlist=", 6) == 0) {
			
			file.name.data = value[i].data + 6;
			file.name.len = value[i].len - 6;
    		file.log = cf->log;
			
			file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);

			if (file.fd == NGX_INVALID_FILE) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_open_file_n " \"%s\" failed", file.name.data);
		        return NGX_CONF_ERROR;
		    }

			if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
		        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
		                           ngx_fd_info_n " \"%s\" failed", file.name.data);
		        goto failed;
		    }

			fsize = (size_t) ngx_file_size(&fi);
			base = ngx_palloc(cf->pool, fsize + 1);
		    if (base == NULL) {
		        goto failed;
		    }

    		n = ngx_read_file(&file, base, fsize, 0);
			if (n == NGX_ERROR) {
		        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
		                           ngx_read_file_n " \"%s\" failed", file.name.data);
		        goto failed;
		    }

			if ((size_t) n != fsize) {
		        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
		            ngx_read_file_n " \"%s\" returned only %z bytes instead of %z",
		            file.name.data, n, fsize);
		        goto failed;
		    }
			
			if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_close_file_n " \"%s\" failed", file.name.data);
		    }

			/* parse whitelist */
			last = base;

			for (p=base+n;p>=base;p--) {
				if (*p != ' ' && *p != '\t' && *p != '\n' && *p != CR && *p != LF && *p != '\0') {
					break;
				}
			}

			/* config file maybe have no '\n' in the end */
			*++p = '\n';
			n = p - base + 1;

			for (;;) {
				
				p = last;
				while((last != base + n -1 ) && (*last != '\n') && (*last != CR) && (*last != LF))last++;

				/* skip empty line and notes line*/		
				SKIPSPACE(p,last)

				if (p == last || p[0] == '#') {
					if (last++ == base + n -1) {
						break;
					}
					continue;
				}
				if (last - p < (int)ngx_strlen("0.0.0.0")) {
					break;
				}

				ngx_str_t buf;

				p1 = p;
				GETSPACE(p1,last)

				/* get left ip */
				ewl = ngx_array_push(wlist);
				
				if (p1 >= last) { /* signal ip */
						
					start = ngx_inet_addr(p, p1 - p);
					if (start == INADDR_NONE) {
						buf.data = p;
						buf.len = p1 - p ;
				        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"signal: parse left ip failed: \"%V\"", &buf);
						return NGX_CONF_ERROR;
				    }
					
					start = ntohl(start);
					end = start;
				} else {
				
					start = ngx_inet_addr(p, p1 - p);
					if (start == INADDR_NONE) {
				        buf.data = p;
						buf.len = p1 - p ;
				        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"region: parse left ip failed: \"%V\"", &buf);
						return NGX_CONF_ERROR;
				    }				
					start = ntohl(start);

					SKIPSPACE(p1,last)
					
					if (p1 == last -1) {		/* only signal ip */		
						end = start;
					} else {					/* ip region */
					
						end = ngx_inet_addr(p1, last - p1);
						if (end == INADDR_NONE) {
					        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"parse right ip failed");
							return NGX_CONF_ERROR;
					    }					
						end = ntohl(end);
					}
				}

				if (start > end) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"ip error: start big than end, %u,%u", start, end);
					return NGX_CONF_ERROR;
				}
				
				ewl->left = start;
				ewl->right = end;

				ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,"whitelist add: start - end: %lu,%lu", start, end);

				if (last++ == base + n -1) {
					break;
				}	
			}
			
			continue;
		}
		

		if (value[i].data[0] == '$') {

			value[i].len--;
			value[i].data++;

			ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_number_ctx_t));
			if(ctx == NULL) {
				return NGX_CONF_ERROR;
			}

			ctx->index = ngx_http_get_variable_index(cf, &value[i]);
			if (ctx->index == NGX_ERROR) {
				return NGX_CONF_ERROR;
			}

			ctx->var = value[i];

			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
	}

	if (name.len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"\"%V\" must have \"zone\" parameter",
						&cmd->name);
		return NGX_CONF_ERROR;
	}

	if (ctx == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"no variable is defined for %V \"%V\"",
						&cmd->name, &name);
		return NGX_CONF_ERROR;
	}

	ctx->rate = rate;
	ctx->interval = scale;
	ctx->interval_forbid = forbid;
	ctx->wlist = wlist;
	ctx->bwlimit = fbwlimit;

	shm_zone = ngx_shared_memory_add(cf, &name, size,
									&ngx_http_limit_req_number_module);
	if(shm_zone == NULL) {
		return NGX_CONF_ERROR;
	}

	if (shm_zone->data) {
		ctx = shm_zone->data;
		
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to variable \"%V\"",
                           &cmd->name, &name, &ctx->var);

		return NGX_CONF_ERROR;
	}

	shm_zone->init = ngx_http_limit_req_number_init_zone;
	shm_zone->data = ctx;

	return NGX_CONF_OK;

failed:
	ngx_array_destroy(wlist);
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file.name.data);
    }
	return NGX_CONF_ERROR;
}

static char *
ngx_http_limit_req_number(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_limit_req_number_conf_t  *lrcf = conf;

	ngx_str_t                   *value, s;
	ngx_uint_t                   i;
	ngx_shm_zone_t              *shm_zone;

	value = cf->args->elts;

	shm_zone = NULL;

	for (i = 1; i < cf->args->nelts; i++) {

		if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

			s.len = value[i].len - 5;
			s.data = value[i].data + 5;

			shm_zone = ngx_shared_memory_add(cf, &s, 0,
													&ngx_http_limit_req_number_module);

			if(shm_zone == NULL) {
				return NGX_CONF_ERROR;
			}
				
			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
		return NGX_CONF_ERROR;
	}

	if (shm_zone == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"\"%V\" must have \"zone\" parameter",
						&cmd->name);
		return NGX_CONF_ERROR;
	}

	if (shm_zone->data == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"unknown limit_req_number_zone \"%V\"",
						&shm_zone->shm.name);
		return NGX_CONF_ERROR;
	}

	lrcf->shm_zone = shm_zone;

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_limit_req_number_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_http_limit_req_number_ctx_t  *octx = data;

	ngx_http_limit_req_number_ctx_t 	*ctx;

	ctx = shm_zone->data;

	if(octx) {
		if (ngx_strcmp(ctx->var.data, octx->var.data) != 0) {
			ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
						"limit_req_number \"%V\" uses the \"%V\" variable "
						"while previously it used the \"%V\" variable",
						&shm_zone->shm.name, &ctx->var, &octx->var);
			return NGX_ERROR;
		}
		
		ctx->sh = octx->sh;
		ctx->shpool = octx->shpool;

		return NGX_OK;

	}

	ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

	if (shm_zone->shm.exists) {
		ctx->sh = ctx->shpool->data;

		return NGX_OK;
	}

	ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_req_number_shctx_t));
	if(ctx->sh == NULL) {
		return NGX_ERROR;
	}

	ctx->shpool->data = ctx->sh;

	ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
				ngx_http_limit_req_number_rbtree_insert_value);

	ngx_queue_init(&ctx->sh->queue);

	return NGX_OK;
}

static void
ngx_http_limit_req_number_rbtree_insert_value(ngx_rbtree_node_t *temp,
	ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
	ngx_rbtree_node_t          **p;
	ngx_http_limit_req_number_node_t   *lrn, *lrnt;

	for ( ;; ) {

		if (node->key < temp->key) {

			p = &temp->left;

		} else if (node->key > temp->key) {

			p = &temp->right;

		} else {
		
			lrn = (ngx_http_limit_req_number_node_t *) node;
			lrnt = (ngx_http_limit_req_number_node_t *) temp;

			p = (ngx_memn2cmp(lrn->name, lrnt->name, lrn->len, lrnt->len) < 0)
				? &temp->left : &temp->right;
		}

		if (*p == sentinel) {
			break;
		}
	
		temp = *p;
	}

	*p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static ngx_http_limit_req_number_node_t *
ngx_http_limit_req_number_lookup(ngx_rbtree_t *tree, u_char *name, size_t size, uint32_t hash)
{
	ngx_int_t                   rc;
	ngx_rbtree_node_t          *node, *sentinel;
	ngx_http_limit_req_number_node_t  *lr;

	node = tree->root;
	sentinel = tree->sentinel;

	while (node != sentinel) {

		if (hash < node->key) {
			node = node->left;
			continue;
		}

		if (hash > node->key) {
			node = node->right;
			continue;
		}

		lr = (ngx_http_limit_req_number_node_t *) node;

		rc = ngx_memn2cmp(name, lr->name, size, (size_t) lr->len);

		if (rc == 0) {
			return lr;
		}

		node = (rc < 0) ? node->left : node->right;
	}

	return NULL;
	
}

static ngx_int_t
ngx_http_limit_req_number_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_limit_req_number_handler;

	return NGX_OK;

}
