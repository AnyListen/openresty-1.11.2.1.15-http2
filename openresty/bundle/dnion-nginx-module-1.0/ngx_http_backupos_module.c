#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_proxy_module.h"

typedef struct {
	//backup os
	ngx_http_upstream_srv_conf_t	*backupos_uscf;
	ngx_http_upstream_main_conf_t	*umcf;
}ngx_http_backupps_loc_conf_t;

static ngx_int_t ngx_http_backupos_init(ngx_conf_t *cf);
static void* ngx_http_backupos_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_backupos_merge_loc_conf(ngx_conf_t *cf,void *parent,void *child);
static char *ngx_http_backupos_get(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static ngx_int_t ngx_http_backupos_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_backupos_set_header(ngx_http_request_t *r, ngx_str_t *new_host, ngx_str_t *host, ngx_str_t *parsed_uri);

static ngx_command_t ngx_http_backupos_commands[] = {

	{ ngx_string("backup_os"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_http_backupos_get,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

	ngx_null_command

};

static ngx_http_module_t ngx_http_backupos_module_ctx={
	NULL,                                  /* preconfiguration */
	ngx_http_backupos_init,	               /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_backupos_create_loc_conf,        /* create location configuration */
	ngx_http_backupos_merge_loc_conf          /* merge location configuration */
};

ngx_module_t  ngx_http_backupos_module = {
	NGX_MODULE_V1,
	&ngx_http_backupos_module_ctx,		   /* module context */
	ngx_http_backupos_commands,			   /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,								   /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,            					   /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_backupos_handler(ngx_http_request_t *r)
{
	ngx_uint_t i;
	ngx_str_t *host;
	ngx_peer_connection_t				*pc;
	ngx_http_upstream_main_conf_t		*umcf;
	ngx_http_upstream_srv_conf_t		**uscfp;
	ngx_http_upstream_srv_conf_t		*backupos_uscf;
	ngx_http_backupps_loc_conf_t		*bucf;
	ngx_http_upstream_srv_conf_t		*check_uscf = NULL;

	if(r->upstream != NULL || r != r->main || r->gslb_dispatch){
		return NGX_DECLINED;
	}

	bucf = ngx_http_get_module_loc_conf(r,ngx_http_backupos_module);

	backupos_uscf = bucf->backupos_uscf;
	if(backupos_uscf == NULL){
		return NGX_DECLINED;
	}
	
	host = ngx_http_proxy_get_upstream(r) ;
	umcf = bucf->umcf;

	if( host == NULL){
		return NGX_DECLINED;
	}

	uscfp = umcf->upstreams.elts;
	for(i = 0; i < umcf->upstreams.nelts; i++)
	{
		if(host->len == uscfp[i]->host.len && ngx_memcmp(host->data, uscfp[i]->host.data, host->len) == 0) {
			//found
			check_uscf = uscfp[i];
			break;
		}
	}

	if(check_uscf == NULL){
		return NGX_DECLINED;
	}

	/* check ip is health */
	r->upstream = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
	if(r->upstream == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->backupos_request = 1;
	if(check_uscf->peer.init(r, check_uscf) != NGX_OK){
		r->backupos_request = 0;
		return NGX_DECLINED;
	}
	r->backupos_request = 0;

	pc = &r->upstream->peer;

	if(pc->get(pc, pc->data) == NGX_OK){
			r->upstream = NULL;
			return NGX_DECLINED;
	}

	/*	get backupos ip  */
	r->upstream = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
	if(r->upstream == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->backupos_request = 1;
	if(backupos_uscf->peer.init(r, backupos_uscf) != NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	r->backupos_request = 0;

	pc = &r->upstream->peer;
	if(pc->get(pc, pc->data) != NGX_OK){
		r->upstream = NULL;
		return NGX_DECLINED;
	}

	//302 redirect
	if(ngx_http_backupos_set_header(r, pc->name, &r->headers_in.server, &r->unparsed_uri) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->redirect302_desip.len = pc->name->len;
	r->redirect302_desip.data = pc->name->data;
	
	return NGX_HTTP_MOVED_TEMPORARILY;	
}


static char *ngx_http_backupos_get(ngx_conf_t *cf,ngx_command_t *cmd,void *conf)
{
	ngx_str_t		*value;
	ngx_uint_t		i;
	ngx_http_upstream_main_conf_t	*umcf;
	ngx_http_upstream_srv_conf_t	**uscfp;
	ngx_http_backupps_loc_conf_t	*bulc = conf;

	value = cf->args->elts;
	umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
	uscfp = umcf->upstreams.elts;

	for(i = 0; i < umcf->upstreams.nelts; i++){
		if(value[1].len == uscfp[i]->host.len && ngx_strcmp(value[1].data, uscfp[i]->host.data) == 0) {
			bulc->backupos_uscf = uscfp[i];
			break;
		}
	}

	if(bulc->backupos_uscf == NGX_CONF_UNSET_PTR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, " no upstream name match \"%V\"", &value[1]);
		return NGX_CONF_ERROR;
	}

	bulc->umcf = umcf;

	return NGX_CONF_OK;
}

static void* ngx_http_backupos_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_backupps_loc_conf_t *conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_backupps_loc_conf_t));
	if(conf == NULL){
		return NULL;
	}

	conf->backupos_uscf = NGX_CONF_UNSET_PTR;
	conf->umcf = NGX_CONF_UNSET_PTR;

	return conf;
}

static char * ngx_http_backupos_merge_loc_conf(ngx_conf_t *cf,void *parent,void *child)
{
	ngx_http_backupps_loc_conf_t	*prev = parent;
	ngx_http_backupps_loc_conf_t	*conf = child;

	ngx_conf_merge_ptr_value(conf->backupos_uscf, prev->backupos_uscf, NULL);
	ngx_conf_merge_ptr_value(conf->umcf, prev->umcf, NULL);

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_backupos_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	cmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if(h == NULL){
		return NGX_ERROR;
	}

	*h = ngx_http_backupos_handler;
	
	return NGX_OK;
}

static ngx_int_t ngx_http_backupos_set_header(ngx_http_request_t *r, ngx_str_t *new_host, ngx_str_t *host, ngx_str_t *parsed_uri) 
{
	u_char			*last;
	ngx_str_t		uri;
	ngx_table_elt_t		*h;

	h = ngx_list_push(&r->headers_out.headers);
	if( h == NULL ){
		return NGX_ERROR;
	}
	
	uri.len = ngx_strlen("http://") + new_host->len + 1 + host->len + parsed_uri->len;
	uri.data = ngx_palloc(r->pool, uri.len);
	if( uri.data == NULL ){
		return NGX_ERROR;
	}

	last = uri.data;
	last = ngx_copy( last, "http://", ngx_strlen("http://") );
	last = ngx_copy( last, new_host->data, new_host->len );
	*last++ = '/';
	last = ngx_copy( last, host->data, host->len );
	last = ngx_copy( last, parsed_uri->data, parsed_uri->len);

	h->value.len = uri.len;
	h->value.data = uri.data;

	h->hash = 1;
	ngx_str_set( &h->key, "Location");

	r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
	r->keepalive = 0;

	return NGX_OK;	

}
