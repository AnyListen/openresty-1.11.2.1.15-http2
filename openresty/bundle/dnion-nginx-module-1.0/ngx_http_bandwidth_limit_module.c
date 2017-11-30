/*
 * Copyright (C) Sogou, Inc
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_json.h"
#include "ngx_http_bandwidth_limit_module.h"
#include "ngx_http_rpc_module.h"

static void ngx_http_bandwidth_limit_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_bandwidth_limit_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_bandwidth_limit_handler(ngx_http_request_t *r);

static void *ngx_http_bandwidth_limit_lookup(void *conf, ngx_uint_t hash,
        ngx_str_t *key);

static void *ngx_http_bandwidth_limit_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_bandwidth_limit_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_bandwidth_limit_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_bandwidth_limit_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);

static ngx_http_bandwidth_limit_main_conf_t    *main_conf=NULL;



static ngx_http_module_t ngx_http_bandwidth_limit_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_bandwidth_limit_init,              /* postconfiguration */

    ngx_http_bandwidth_limit_create_main_conf,  /* create main configuration */
    ngx_http_bandwidth_limit_init_main_conf,    /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_bandwidth_limit_create_loc_conf,   /* create location configration */
    ngx_http_bandwidth_limit_merge_loc_conf     /* merge location configration */
};


static ngx_command_t ngx_http_bandwidth_limit_commands[] = {

	{ ngx_string("bandwidth_limit_flag"),
	 NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_bandwidth_limit_loc_conf_t, limit_flag),
     NULL },

    ngx_null_command
};


ngx_module_t ngx_http_bandwidth_limit_module = {
    NGX_MODULE_V1,
    &ngx_http_bandwidth_limit_module_ctx,
    ngx_http_bandwidth_limit_commands,
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_http_bandwidth_limit_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_http_bandwidth_limit_node_t      *cn, *cnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */
            cn = (ngx_http_bandwidth_limit_node_t *) node;
            cnt = (ngx_http_bandwidth_limit_node_t *) temp;

            p = (ngx_memn2cmp(cn->key, cnt->key, cn->len, cnt->len) < 0)
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

ngx_int_t
ngx_http_revc_bandwidth_limit_handler(ngx_connection_t *c)
{
	ngx_str_t				subbody,hostname,step;
	size_t                  len;
	ngx_log_t				*log;
	int					x, n;
	u_char						            *ps, *pos, *last, *pe, *pl;
	ngx_http_bandwidth_limit_val_t			*ls_v;
	ngx_http_bandwidth_limit_node_t         *ssn;
	ngx_http_bandwidth_limit_sh_t      *sctx;
	uint32_t                                hash;
	ngx_http_bandwidth_limit_main_conf_t	*conf;
	cJSON				*oj, *item, *hostNode, *bandwidthNode,*limitNode;
	cJSON				*min_rateNode, *stepNode, *durationNode, *discardNode;
	ngx_buf_t					*b;
	ngx_http_rpc_server_t		*s;
	ngx_uint_t	                vstride;
	ngx_uint_t	                v;

	s = c->data;
	b = s->rb;
	conf = main_conf;
	sctx = &conf->sctx;
	
	log = c->log;
        
        
	pl = ngx_strlchr(b->pos, b->last, '[');
	if(pl == NULL) {
		return NGX_ERROR;
	}
	subbody.data = pl;
	subbody.len = b->last - pl;
	oj = cJSON_Parse((const char *)subbody.data);
	if (oj == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw root) format, %V", &subbody);
		return NGX_ERROR;
	}

	n = cJSON_GetArraySize(oj);

	for(x = 0; x < n; x++) {
		item = cJSON_GetArrayItem(oj, x);
		hostNode = cJSON_GetObjectItem(item, "host");	
		if( hostNode == NULL) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw host) format, %V", &subbody);
			goto invalid_recv_fail;
		}
		
	    bandwidthNode = cJSON_GetObjectItem(item, "bandwidth");
		if( bandwidthNode == NULL) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw bandwidth) format, %V", &subbody);
			goto invalid_recv_fail;
		}
		
	    limitNode = cJSON_GetObjectItem(item, "curbw");
		if( limitNode == NULL) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw curbw) format, %V", &subbody);
			goto invalid_recv_fail;
		}
		
	    min_rateNode = cJSON_GetObjectItem(item, "min_rate");
		if( min_rateNode == NULL) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw min_rate) format, %V", &subbody);
			goto invalid_recv_fail;
		}
		
	    stepNode = cJSON_GetObjectItem(item, "step");
		if( stepNode == NULL) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw step) format, %V", &subbody);
			goto invalid_recv_fail;
		}
		
	    durationNode = cJSON_GetObjectItem(item, "duration");
		if( durationNode == NULL) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw duration) format, %V", &subbody);
			goto invalid_recv_fail;
		}
		
	    discardNode = cJSON_GetObjectItem(item, "discard");
		if( discardNode == NULL) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw discard) format, %V", &subbody);
			goto invalid_recv_fail;
		}
		
		hostname.len = ngx_strlen(hostNode->valuestring);
		hostname.data = hostNode->valuestring;
		hash = ngx_crc32_short(hostname.data, hostname.len);
		ssn = ngx_http_bandwidth_limit_lookup(sctx, hash, &hostname);
		if (ssn == NULL) {
			len  = sizeof(ngx_http_bandwidth_limit_node_t) + hostname.len + 1;
			ssn = ngx_pcalloc(conf->pool, len);
			if (ssn == NULL) {
				goto invalid_recv_fail;
			}

			ssn->node.key = hash;
			ssn->len = hostname.len;
			ngx_memcpy(ssn->key, hostname.data, hostname.len);
			ssn->key[hostname.len] = '\0';
			ssn->last_update = 0;
			if (ngx_array_init(&ssn->limit_var, conf->pool, 20, sizeof(ngx_http_bandwidth_limit_val_t))
				!= NGX_OK)	{
				goto invalid_recv_fail;
			}
			ngx_rbtree_insert(&sctx->rbtree, &ssn->node);
		}
		ssn->last_update = ngx_current_msec;
		ssn->limit = (size_t)limitNode->valueint;
		ssn->basic_bandwidth = (size_t)bandwidthNode->valueint;
		ssn->min_rate = (size_t)min_rateNode->valueint;
		ssn->limit_interval= (ngx_msec_t)durationNode->valueint;
		ssn->percent= (ngx_uint_t)discardNode->valueint;
		step.len = ngx_strlen(stepNode->valuestring);
	    step.data = stepNode->valuestring;

        ssn->limit_var.nelts = 0;
		
        //ÏÞËÙ²½·ù
		pos = step.data;
		last = step.data + step.len;
		while(pos < last){
			if(ssn->limit_var.nelts >= 20 ) {
				ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw step) too long(>20), %V", &subbody);
				break;
			}
			
			ps = pos;
			while(*pos && *pos != ',' && pos != last) pos ++;
				pe = ngx_strlchr(ps, pos, '=');
			if(pe == NULL) {
				ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw step1) format, %V", &subbody);
				goto invalid_recv_fail;
			}

			vstride = ngx_atoi(ps,pe - ps );
			if(vstride == (int)NGX_ERROR) {
				ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw step3) format, %V", &subbody);
				goto invalid_recv_fail;
			}
			pe ++;
		    v = ngx_atoi(pe, pos-pe);
	
			if(v == NGX_ERROR) {
				ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw step4) format, %V", &subbody);
				goto invalid_recv_fail;
			}
			pos ++;

			ls_v = ngx_array_push(&ssn->limit_var);
			if(ls_v == NULL) {
				ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid json(limitbw step2) format, %V", &subbody);
				goto invalid_recv_fail;
			}
			ls_v->vstride = vstride;
			ls_v->v = v;

		}

		
	}
	cJSON_Delete(oj);
    return NGX_OK;
	
invalid_recv_fail:
	cJSON_Delete(oj);
	return NGX_ERROR;

	
}

static ngx_int_t
ngx_http_bandwidth_limit_handler(ngx_http_request_t *r)
{
    size_t                              limit;
    uint32_t                            hash;
    ngx_int_t                          j,overstep;
	ngx_http_bandwidth_limit_sh_t           *sctx;
    ngx_http_bandwidth_limit_node_t         *ssn;
    ngx_http_bandwidth_limit_loc_conf_t     *rlcf;
	ngx_http_bandwidth_limit_main_conf_t    *rmcf;
	ngx_msec_t                     last_update;
	ngx_http_bandwidth_limit_val_t *limit_v;

	rmcf = ngx_http_get_module_main_conf(r, ngx_http_bandwidth_limit_module);
	sctx =  &rmcf->sctx;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_bandwidth_limit_module);

   if (rlcf->limit_flag ) {
	   
	    hash = ngx_crc32_short(r->headers_in.server.data, r->headers_in.server.len);
	    ssn = ngx_http_bandwidth_limit_lookup(sctx, hash, &r->headers_in.server);
	    
		if (ssn == NULL) {
			return NGX_DECLINED;
		}

		limit = ssn->limit;
		last_update = ssn->last_update;

		if(limit > ssn->basic_bandwidth && (ngx_current_msec - last_update) <= ssn->limit_interval){
			overstep = ((limit - ssn->basic_bandwidth)*100)/ssn->basic_bandwidth;
		limit_v = ssn->limit_var.elts;
			for (j = (ssn->limit_var.nelts - 1); j >= 0 ; j--) {
				if( overstep > limit_v[j].vstride){
					if(j == (ssn->limit_var.nelts - 1)){
						if(ssn->percent != 0){
						   ssn->count ++;
							if(ssn->count >= ssn->percent){
								ssn->count = 0;
								return NGX_HTTP_FORBIDDEN;
							}
						}
					}
					else{
						ssn->count = 0;
					}
					r->limit_rate = limit_v[j].v*ssn->min_rate/100;
					return NGX_DECLINED;
				}
		    }
		}
		ngx_rbtree_delete(&sctx->rbtree,&ssn->node);
   	}
    return NGX_DECLINED;
}



static void *
ngx_http_bandwidth_limit_lookup(void *conf, ngx_uint_t hash, ngx_str_t *key)
{
    ngx_int_t                       rc;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_bandwidth_limit_node_t     *ssn;
    ngx_http_bandwidth_limit_sh_t     *ctx = conf;

    node = ctx->rbtree.root;
    sentinel = ctx->rbtree.sentinel;
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */
        ssn = (ngx_http_bandwidth_limit_node_t *)node;

        rc = ngx_memn2cmp(key->data, ssn->key, key->len, ssn->len);
        if (rc == 0){
            return ssn;
        }

        node = (rc < 0) ? node->left : node->right;
    }
    return NULL;
}

static void *
ngx_http_bandwidth_limit_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_bandwidth_limit_main_conf_t   *rmcf;
    rmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_bandwidth_limit_main_conf_t));
    if (rmcf == NULL) {
        return NULL;
    }

	rmcf->pool = cf->pool;
	
	main_conf = rmcf;

    return rmcf;
}

static void *
ngx_http_bandwidth_limit_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_bandwidth_limit_loc_conf_t *rlcf;
    rlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_bandwidth_limit_loc_conf_t));
    if (rlcf == NULL) {
        return NULL;
    }

	rlcf->limit_flag = NGX_CONF_UNSET;
	

    return rlcf;
}

static char *
ngx_http_bandwidth_limit_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_bandwidth_limit_loc_conf_t *prev = parent;
    ngx_http_bandwidth_limit_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->limit_flag, prev->limit_flag, 0);
    return NGX_CONF_OK;
}

static char *ngx_http_bandwidth_limit_init_main_conf(ngx_conf_t *cf, void *conf)
{  
	ngx_http_bandwidth_limit_sh_t      *sctx;
	ngx_http_bandwidth_limit_main_conf_t    *rmcf = conf;
	ngx_http_bandwidth_limit_ctx_t          *ctx;
    ctx = &rmcf->ctx;
	sctx = &rmcf->sctx;
	
	ctx->err_msg = ngx_create_temp_buf(cf->pool, LBW_MSG_SIZE);
	if(ctx->err_msg == NULL) {
	   return NGX_CONF_ERROR;
	}
	ctx->body_buf = ngx_create_temp_buf(cf->pool, BLW_BODY_SIZE);
	if(ctx->body_buf == NULL) {
	   return NGX_CONF_ERROR;
	}

        ngx_rbtree_init(&sctx->rbtree, &sctx->sentinel,
            ngx_http_bandwidth_limit_rbtree_insert_value);
	return NGX_CONF_OK;

}

static ngx_int_t
ngx_http_bandwidth_limit_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt               *h;
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_bandwidth_limit_main_conf_t   *rmcf;
    rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_bandwidth_limit_module);


    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_bandwidth_limit_handler;

    return NGX_OK;
}

