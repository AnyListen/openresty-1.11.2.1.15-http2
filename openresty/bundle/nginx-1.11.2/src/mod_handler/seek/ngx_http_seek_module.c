#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_flag_t  seek;
	ngx_str_t start_name;
	ngx_str_t end_name;
}ngx_http_seek_loc_conf_t;


static ngx_int_t ngx_http_seek_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_seek_init(ngx_conf_t *cf);

static void * ngx_http_seek_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_seek_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_seek_commands[] = {
	{
		ngx_string("seek"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_seek_loc_conf_t, seek),
		NULL
	},

	{ ngx_string("seek_start_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_seek_loc_conf_t, start_name),
		NULL },

	{ ngx_string("seek_end_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_seek_loc_conf_t, end_name),
		NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_seek_module_ctx = {
	NULL,
	ngx_http_seek_init,
	NULL,
	NULL,
	NULL,
	NULL,
	ngx_http_seek_create_loc_conf,
	ngx_http_seek_merge_loc_conf
};

ngx_module_t ngx_http_seek_module = {
	NGX_MODULE_V1,
	&ngx_http_seek_module_ctx,
	ngx_http_seek_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_seek_handler(ngx_http_request_t *r)
{
	ngx_http_seek_loc_conf_t   *slcf;
	slcf = ngx_http_get_module_loc_conf(r, ngx_http_seek_module);
	if(!slcf->seek) {
		return NGX_OK;
	}
	///convert start end ==> range
	ngx_table_elt_t *range = r->headers_in.range;

	char *pstart, *pend;
	int start = 0;
	int end = 0;
	u_char *last;

	char args_xx[128] = "";
	char start_xx[128] = "";
	char end_xx[128] = "";

	pstart = NULL;
	pend = NULL;
	if(r->args.len !=0) {
		strncpy(args_xx, (char *)r->args.data, r->args.len);
		strncpy(start_xx,(char *)slcf->start_name.data, slcf->start_name.len);
		strncpy(end_xx, (char *)slcf->end_name.data, slcf->end_name.len);
		//pstart = ngx_strstrn(r->args.data, slcf->start_name.data,slcf->start_name.len);
		//pend = ngx_strstrn(r->args.data, slcf->end_name.data, slcf->end_name.len);
		pstart = strstr(args_xx, start_xx);
		pend = strstr(args_xx, end_xx);

		if(pstart) {
			last = (u_char*)pstart + (slcf->start_name.len+1);
			start = atoi((char *)last);
		}
		if(pend) {
			last = (u_char*)pend+ (slcf->end_name.len+1);
			end = atoi((char *)last);
		}

		if(start <= 0)
			start = 0;
		if(end <=0) 
			end = 0;
		if(start > end)
			end = 0;
		
		if(start != 0 || end != 0) {
			r->headers_in.range = ngx_list_push(&r->headers_in.headers);
			if(r->headers_in.range == NULL) {
				return NGX_ERROR;
			}

			range = r->headers_in.range;
			range->hash = 1;

			range->key.data = ngx_palloc(r->pool, 5);
			if(range->key.data == NULL) {
				return NGX_ERROR;
			}
			range->key.len = 5;
			last = ngx_copy(range->key.data, "Range", 5);
			
			range->value.data = ngx_pcalloc(r->pool, 7 + r->args.len);
			if(range->value.data == NULL) {
				return NGX_ERROR;
			}
		}else {
			return NGX_OK;
		}
	} else {
		return NGX_OK;
	}

	if(start !=0 && end !=0) {
		last = ngx_sprintf(range->value.data, "bytes=%d-%d",start,end);
	} else if (start != 0){
		last = ngx_sprintf(range->value.data, "bytes=%d-",start);
	} else {
		last = ngx_sprintf(range->value.data, "bytes=0-%d",end);
	}
	range->value.len = last-range->value.data;

	//r->args.data = NULL;
	//r->args.len = 0;
	return NGX_OK;
}

static ngx_int_t ngx_http_seek_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_seek_handler;

	return NGX_OK;
}

static void * ngx_http_seek_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_seek_loc_conf_t *slcf;
	slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_seek_loc_conf_t));
	if(slcf == NULL) {
		return NULL;
	}
	slcf->seek = NGX_CONF_UNSET;
	return  slcf;
}

static char * ngx_http_seek_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_seek_loc_conf_t *prev = parent;
	ngx_http_seek_loc_conf_t *conf = child;
	ngx_conf_merge_value(conf->seek, prev->seek, 0);
	ngx_conf_merge_str_value(conf->start_name,prev->start_name,"start");
	ngx_conf_merge_str_value(conf->end_name,prev->end_name,"end");
	return NGX_CONF_OK;
}

