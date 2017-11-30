#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	size_t			ls_default;
	size_t			ls_after;
} ngx_http_args_ls_val_t;

typedef struct {
	ngx_str_t			ls_ls_key;
	ngx_str_t			ls_uls_size_key;
	ngx_array_t			ls_data;
}ngx_http_args_ls_loc_conf_t;

static char *ngx_http_args_ls_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_args_ls_handler(ngx_http_request_t *r);
static void *ngx_http_args_ls_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_args_ls_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_args_ls_init(ngx_conf_t *cf);

static ngx_command_t  ngx_http_args_ls_commands[] = {
	{ ngx_string("args_limit_speed_key"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

	{ ngx_string("args_limit_speed_size_key"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_args_ls_loc_conf_t, ls_uls_size_key),
	  NULL },

	{ ngx_string("limit_speed_value"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
	  ngx_http_args_ls_value,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

	ngx_null_command	
};

static ngx_http_module_t  ngx_http_args_ls_module_ctx = {
	NULL,
	ngx_http_args_ls_init,					/* postconfiguration */

	NULL,								/* create main configuration */
	NULL,								/* init main configuration */

	NULL,								/* create server configuration */
	NULL,								/* merge server configuration */

	ngx_http_args_ls_create_loc_conf,		/* create location configuration */
	ngx_http_args_ls_merge_loc_conf		/* merge location configuration */
};


ngx_module_t  ngx_http_args_ls_module = {
	NGX_MODULE_V1,
	&ngx_http_args_ls_module_ctx,	    /* module context */
	ngx_http_args_ls_commands,					/* module directives */
	NGX_HTTP_MODULE,						/* module type */
	NULL,									/* init master */
	NULL,									/* init module */
	NULL,									/* init process */
	NULL,									/* init thread */
	NULL,									/* exit thread */
	NULL,									/* exit process */
	NULL,									/* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_args_ls_handler(ngx_http_request_t *r)
{
	ngx_http_args_ls_loc_conf_t  *alcf;
	ngx_http_args_ls_val_t *aplv;
	ngx_str_t		          vl;
	ngx_str_t		          vla;
	size_t                    ls;
	size_t                    las;

	alcf = ngx_http_get_module_loc_conf(r, ngx_http_args_ls_module);

	if( r != r->main || alcf->ls_data.nelts == 0){
		return NGX_DECLINED;
	}
       aplv = &alcf->ls_data.elts[0];
	
	if(r->args.len == 0)
	{
		ls = aplv->ls_default;
		las = aplv->ls_after;
	}
	else
	{
	   if (ngx_http_arg(r, alcf->ls_ls_key.data, alcf->ls_ls_key.len,&vl) == NGX_OK) 
	   {
	        ls = ngx_parse_size(&vl);
			
			if (ls == (size_t)NGX_ERROR) {
				ls = aplv->ls_default;
			}
	    }
	    else{
			ls = aplv->ls_default;
	    }

	    if (ngx_http_arg(r, alcf->ls_uls_size_key.data, alcf->ls_uls_size_key.len,&vla) == NGX_OK) 
	    {
	        las = ngx_parse_size(&vla);
			
			if (las == (size_t)NGX_ERROR) {
				las = aplv->ls_after;
			}
	     }
	     else{
			las = aplv->ls_after;
	     }	
			
	}
        r->limit_rate = ls;
        r->limit_rate_after = las;
	return NGX_DECLINED;
}

static char *
ngx_http_args_ls_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_args_ls_loc_conf_t *alcf = conf;
	ngx_str_t					*value;
	ngx_str_t		         vl;
	ngx_str_t		         vla;
	size_t					 ls_default;
	size_t					 ls_after;
	ngx_http_args_ls_val_t   *as;
		
	value = cf->args->elts;
	ls_default = 0;
	ls_after = 0;

	//没有配限速值
	if(cf->args->nelts == 1)
	{
		return NGX_CONF_OK;
	}
	//配了ls_default或者是ls_after
	else if(cf->args->nelts == 2){	
		if(ngx_strncmp(value[1].data, "default=", 8) == 0) {
			vl.data = &value[1].data[8];
			vl.len = value[1].len - 8;
			ls_default = ngx_parse_size(&vl);
			if(ls_default == (size_t)NGX_ERROR) {
				return NGX_CONF_ERROR;
			}
		} 
		else if(ngx_strncmp(value[1].data, "limit_after=", 12) == 0) {
			vla.data = &value[1].data[12];
			vla.len = value[1].len - 12;
			ls_after = ngx_parse_size(&vla);
			if(ls_after == (size_t)NGX_ERROR) {
				return NGX_CONF_ERROR;	
			}
		}
	}
	//配了ls_default和ls_after
	else if(cf->args->nelts == 3){
		if(ngx_strncmp(value[1].data, "default=", 8) == 0) {
			vl.data = &value[1].data[8];
			vl.len = value[1].len - 8;
			ls_default = ngx_parse_size(&vl);
			 if(ls_default == (size_t)NGX_ERROR) {
				 return NGX_CONF_ERROR;
			 }
		} else if(ngx_strncmp(value[1].data, "limit_after=", 12) == 0) {
			vla.data = &value[1].data[12];
			vla.len = value[1].len - 12;
			ls_after = ngx_parse_size(&vla);
			if(ls_after == (size_t)NGX_ERROR) {
				return NGX_CONF_ERROR;
			}

		}

		if(ngx_strncmp(value[2].data, "default=", 8) == 0) {
			vl.data = &value[2].data[8];
			vl.len = value[2].len - 8;
			ls_default = ngx_parse_size(&vl);
			if(ls_default == (size_t)NGX_ERROR) {
				return NGX_CONF_ERROR;
			}
		} 
		else if(ngx_strncmp(value[2].data, "limit_after=", 12) == 0) {
			vla.data = &value[2].data[12];
			vla.len = value[2].len - 12;
			ls_after = ngx_parse_size(&vla);
			if(ls_after == (size_t)NGX_ERROR) {
				return NGX_CONF_ERROR;
			}
		}
	}

	as = ngx_array_push(&alcf->ls_data);
	if(as == NULL)
	{
		return NGX_CONF_ERROR;
	}

        as->ls_default = ls_default;
	as->ls_after = ls_after;

	return NGX_CONF_OK;
}

static void *
ngx_http_args_ls_create_loc_conf(ngx_conf_t *cf)
{
	 ngx_http_args_ls_loc_conf_t  *conf;
	 conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_args_ls_loc_conf_t));
	 if(conf == NULL)
	 {
	 	return NULL;
	 }
		
	 if(ngx_array_init(&conf->ls_data,cf->pool,2,
				 	sizeof(ngx_http_args_ls_val_t))
			 != NGX_OK)
	 {
		return NULL;		 
	 }

	 return conf;
}

static char *
ngx_http_args_ls_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_args_ls_loc_conf_t  *prev = parent;
	ngx_http_args_ls_loc_conf_t  *conf = child;

	if(conf->ls_ls_key.data == NULL && conf->ls_ls_key.len == 0
		&& conf->ls_uls_size_key.data == NULL && conf->ls_uls_size_key.len == 0 && conf->ls_data.nelts == 0)
	{
		conf->ls_ls_key= prev->ls_ls_key;
		conf->ls_uls_size_key= prev->ls_uls_size_key;
		conf->ls_data = prev->ls_data;
	}

	if(conf->ls_ls_key.data == NULL || conf->ls_ls_key.len == 0)
	{
	   ngx_str_set(&conf->ls_ls_key,"limit");
	}

	
	if(conf->ls_uls_size_key.data == NULL || conf->ls_uls_size_key.len == 0)
	{
	   ngx_str_set(&conf->ls_uls_size_key,"ulimit_size");
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_args_ls_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_args_ls_handler;

	return NGX_OK;
}
