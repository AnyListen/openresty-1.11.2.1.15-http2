#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
	ngx_str_t	vname;
	ngx_int_t	v;
}ngx_http_apls_val_t;

typedef struct {
	ngx_array_t			limit_var;
	ngx_int_t			limit_default;
	ngx_int_t			limit_after;
} ngx_http_apls_limit_val_t;

typedef struct {
#if(NGX_PCRE)
	ngx_http_regex_t		*regex;
#endif
	ngx_http_apls_limit_val_t	*var;
	ngx_str_t			name;
}ngx_http_apls_server_t;

typedef struct {
	ngx_str_t			ls_key;
	ngx_array_t			limit_data;
	ngx_hash_combined_t		*names;
#if (NGX_PCRE)
	ngx_uint_t			nregex;
	ngx_http_apls_server_t		*regex;
#endif
}ngx_http_apls_loc_conf_t;

static ngx_http_apls_loc_conf_t *loc_conf=NULL;

static int ngx_libc_cdecl ngx_http_apls_dns_wildcards(const void *one, const void *two);
static char *ngx_http_apls_limit_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_apls_handler(ngx_http_request_t *r);
static void *ngx_http_apls_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_apls_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_apls_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_apls_hash(ngx_conf_t *cf, ngx_http_apls_loc_conf_t *apls);

static ngx_command_t  ngx_http_apls_commands[] = {
	{ ngx_string("aipai_limit_key"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

	{ ngx_string("aipai_limit_value"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
	  ngx_http_apls_limit_value,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

	ngx_null_command	
};

static ngx_http_module_t  ngx_http_apls_module_ctx = {
	NULL,
	ngx_http_apls_init,					/* postconfiguration */

	NULL,								/* create main configuration */
	NULL,								/* init main configuration */

	NULL,								/* create server configuration */
	NULL,								/* merge server configuration */

	ngx_http_apls_create_loc_conf,		/* create location configuration */
	ngx_http_apls_merge_loc_conf		/* merge location configuration */
};


ngx_module_t  ngx_http_apls_module = {
	NGX_MODULE_V1,
	&ngx_http_apls_module_ctx,				/* module context */
	ngx_http_apls_commands,					/* module directives */
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
ngx_http_apls_handler(ngx_http_request_t *r)
{
	ngx_str_t	host;
	ngx_http_apls_loc_conf_t  *alcf;
	ngx_http_apls_limit_val_t *aplv;
	ngx_http_apls_server_t	  *aps;
	ngx_uint_t		  i;
	ngx_int_t                 n;
	u_char		          *p, *last, *end;
	u_char 			*name;
	ngx_str_t		vname;
	ngx_http_apls_val_t	*var;

	alcf = ngx_http_get_module_loc_conf(r, ngx_http_apls_module);

	if( r != r->main || r->dnion_request || alcf->limit_data.nelts == 0){
		return NGX_DECLINED;
	}
	
	host = r->headers_in.server;

	//完全匹配，前匹配，后匹配
	aplv = ngx_hash_find_combined(alcf->names,ngx_hash_key(host.data,host.len),
					host.data,host.len);

	//匹配成功
	if(aplv)
	{
		goto done;
	}

#if (NGX_PCRE)
	if(host.len && alcf->nregex){

		aps = alcf->regex;
		for(i = 0; i < alcf->nregex; i++)
		{
			n = ngx_http_regex_exec(r,aps[i].regex,&host);
				
			if (n == NGX_DECLINED) {
				continue;
			}
			//匹配成功
			if(n == NGX_OK){
				aplv = aps[i].var;
				goto done;
			}
		}
	}
#endif
	return NGX_DECLINED;

done:
	if(r->args.len == 0)
	{
		r->limit_rate = aplv->limit_default * 1024;
		r->limit_rate_after = aplv->limit_after * 1024 * 1024;
	}
	else
	{
		name = ngx_pcalloc(r->pool, alcf->ls_key.len + 2);
		if(name == NULL){
			return NGX_DECLINED;
		}
		last = name;
		last = ngx_cpymem(last, alcf->ls_key.data, alcf->ls_key.len);
		last = ngx_cpymem(last, "=", 1);
		*last = '\0';

		last = r->args.data + r->args.len;

		p = ngx_strnstr(r->args.data, (char*)name, r->args.len);
			
		//"l="?
		if(p)
		{
			if((p[-1] == '?' || p[-1] == '&')) {
				vname.data = p + ngx_strlen(name);
				end =vname.data;
				while(*end && *end != '&' && end != last) end ++;
				vname.len = end - vname.data;

				var = aplv->limit_var.elts;
				for(i=0;i<aplv->limit_var.nelts; i++)
				{
					if(vname.len == var[i].vname.len &&
								ngx_strncmp(vname.data, var[i].vname.data, vname.len) == 0)
						break;	
				}

				if( i == aplv->limit_var.nelts) {
					r->limit_rate = aplv->limit_default * 1024;
				}
				else{
					r->limit_rate = var[i].v * 1024;
				}
			}
			else{
				r->limit_rate = aplv->limit_default * 1024;
			}
			r->limit_rate_after = aplv->limit_after * 1024 * 1024;
		}
		else{
			r->limit_rate = aplv->limit_default * 1024;
			r->limit_rate_after = aplv->limit_after * 1024 * 1024;
		}
			
		}
	return NGX_DECLINED;
}

static char *
ngx_http_apls_limit_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_apls_loc_conf_t *alcf = conf;
	ngx_str_t					*value;
	ngx_int_t					limit_default;
	ngx_int_t					limit_after;
	ngx_http_apls_server_t				*as;
	u_char						*ps, *pos, *last, *pe;
	ngx_http_apls_val_t			*ls_v;
		
	value = cf->args->elts;
	limit_default = 0;
	limit_after = 0;

	if(loc_conf != NULL && loc_conf != alcf)
	{
		if(loc_conf->ls_key.data != NULL && loc_conf->ls_key.len !=0 && loc_conf->limit_data.nelts != 0)
		{
			if(ngx_http_apls_hash(cf, loc_conf) != NGX_OK){
				return NGX_CONF_ERROR; 
			}
		}
	}

	loc_conf = alcf;

	//没有配限速值
	if(cf->args->nelts == 1 || cf->args->nelts == 2)
	{
		return NGX_CONF_OK;
	}
	//配了limit_default或者是limit_after
	else if(cf->args->nelts == 4){	
		if(ngx_strncmp(value[3].data, "default=", 8) == 0) {
			limit_default = ngx_atoi(&value[3].data[8], value[3].len - 8);
			if(limit_default == NGX_ERROR) {
				return NGX_CONF_ERROR;
			}
		} 
		else if(ngx_strncmp(value[3].data, "limit_after=", 12) == 0) {
			limit_after = ngx_atoi(&value[3].data[12], value[3].len - 12);
			if(limit_after == NGX_ERROR) {
				return NGX_CONF_ERROR;	
			}
		}
	}
	//配了limit_default和limit_after
	else if(cf->args->nelts == 5){
		if(ngx_strncmp(value[3].data, "default=", 8) == 0) {
			limit_default = ngx_atoi(&value[3].data[8], value[3].len - 8);
			 if(limit_default == NGX_ERROR) {
				 return NGX_CONF_ERROR;
			 }
		} else if(ngx_strncmp(value[3].data, "limit_after=", 12) == 0) {
			limit_after = ngx_atoi(&value[3].data[12], value[3].len - 12);
			if(limit_after == NGX_ERROR) {
				return NGX_CONF_ERROR;
			}

		}

		if(ngx_strncmp(value[4].data, "default=", 8) == 0) {
			limit_default = ngx_atoi(&value[4].data[8], value[4].len - 8);
			if(limit_default == NGX_ERROR) {
				return NGX_CONF_ERROR;
			}
		} 
		else if(ngx_strncmp(value[4].data, "limit_after=", 12) == 0) {
			limit_after = ngx_atoi(&value[4].data[12], value[4].len - 12);
			if(limit_after == NGX_ERROR) {
				return NGX_CONF_ERROR;
			}
		}
	}

	as = ngx_array_push(&alcf->limit_data);
	if(as == NULL)
	{
		return NGX_CONF_ERROR;
	}

#if (NGX_PCRE)
	as->regex = NULL;
#endif
	as->var = ngx_pcalloc(cf->pool,sizeof(ngx_http_apls_limit_val_t));
	if(as->var == NULL)
	{
		return NGX_CONF_ERROR;
	}
		
	if(ngx_array_init(&as->var->limit_var,cf->pool,10,sizeof(ngx_http_apls_val_t))
										!= NGX_OK)
	{
		return NGX_CONF_ERROR;
	}
	//server对应的限速数据保存在var里面
	//解析限速参数
	pos = value[2].data;
	last = value[2].data + value[2].len;
	while(pos < last){
		ps = pos;
		while(*pos && *pos != ',' && pos != last) pos ++;
		pe = ngx_strlchr(ps, pos, '=');
		if(pe == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
			return NGX_CONF_ERROR;
		}
		ls_v = ngx_array_push(&as->var->limit_var);
		if(ls_v == NULL) {
			return NGX_CONF_ERROR;
		}
		ls_v->vname.data = ps;
		ls_v->vname.len = pe - ps;
		if(ls_v->vname.len == 0) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
			return NGX_CONF_ERROR;
		}

		pe ++;
		ls_v->v = ngx_atoi(pe, pos-pe);

		if(ls_v->v == NGX_ERROR) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
			return NGX_CONF_ERROR;
		}
		pos ++;
	}

	as->var->limit_default = limit_default;
	as->var->limit_after = limit_after;
	as->name = value[1];
		
	//以“~”开头的是正则
	if(value[1].data[0] != '~'){
		ngx_strlow(as->name.data,as->name.data,as->name.len);
		return NGX_CONF_OK;
	}

#if (NGX_PCRE)
	u_char               *p;
	ngx_regex_compile_t   rc;
	u_char                errstr[NGX_MAX_CONF_ERRSTR];
		
	value[1].len--;
	value[1].data++;
	ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

	rc.pattern = value[1];
	rc.err.len = NGX_MAX_CONF_ERRSTR;
	rc.err.data = errstr;
		
	for (p = value[1].data; p < value[1].data + value[1].len; p++) {
		if (*p >= 'A' && *p <= 'Z') {
			rc.options = NGX_REGEX_CASELESS;
			break;
		}
	}

	as->regex = ngx_http_regex_compile(cf, &rc);
	if(as->regex == NULL)
	{
		return NGX_CONF_ERROR;
	}
		
	as->name = value[1];
	return NGX_CONF_OK;
#else
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"using regex \"%V\" "
			"requires PCRE library", &value[1]);
	return NGX_CONF_ERROR;
#endif
}

static ngx_int_t ngx_http_apls_hash(ngx_conf_t *cf, ngx_http_apls_loc_conf_t *apls)
{
	ngx_hash_keys_arrays_t      ha;
	ngx_http_apls_loc_conf_t	*conf;
	ngx_http_apls_server_t		*var;
	ngx_int_t                   rc;
	ngx_hash_init_t             hash;

	ngx_uint_t					cout,s;
#if (NGX_PCRE)
	ngx_uint_t                  regex, i;
	regex = 0;
#endif
	ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

#if (NGX_PCRE)
	regex = 0;
#endif
	conf = apls;
	//如果没有数据 则忽略
	if(conf->ls_key.len == 0 || conf->limit_data.nelts == 0){
		return NGX_OK;
	}	
	ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
	if (ha.temp_pool == NULL) {
		return NGX_ERROR;
	}

	ha.pool = cf->pool;

	if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
		goto failed;
	}

	var = conf->limit_data.elts;
	for(cout = 0; cout < conf->limit_data.nelts; cout++)
	{
			
#if(NGX_PCRE)
		if(var[cout].regex)
		{
			regex++;
			continue;
		}
#endif
		rc = ngx_hash_add_key(&ha, &var[cout].name, var[cout].var,NGX_HASH_WILDCARD_KEY);

		if(rc == NGX_ERROR)
		{
			return NGX_ERROR;
		}

		if (rc == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
						"invalid server name or wildcard \"%V\"",
						&var[cout].name);
			return NGX_ERROR;
		}

		if(rc == NGX_BUSY) {
			ngx_log_error(NGX_LOG_WARN, cf->log, 0,
						"conflicting server name \"%V\" ignored",
						&var[cout].name);

		}
	}

	hash.key = ngx_hash_key_lc;
	hash.max_size = 512;
	hash.bucket_size = 128;
	hash.name = "aipai_server_hash";
	hash.pool = cf->pool;

	if (ha.keys.nelts) {
		hash.hash = &conf->names->hash;
		hash.temp_pool = NULL;

		if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
			goto failed;
		}
	}

	if (ha.dns_wc_head.nelts) {
		ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
				sizeof(ngx_hash_key_t), ngx_http_apls_dns_wildcards);

		hash.hash = NULL;
		hash.temp_pool = ha.temp_pool;

		if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
								ha.dns_wc_head.nelts)
				!= NGX_OK){
			goto failed;
		}
		conf->names->wc_head = (ngx_hash_wildcard_t *) hash.hash;
	}

	if (ha.dns_wc_tail.nelts) {
		ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
					sizeof(ngx_hash_key_t), ngx_http_apls_dns_wildcards);

		hash.hash = NULL;
		hash.temp_pool = ha.temp_pool;

		if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
									ha.dns_wc_tail.nelts)
				!= NGX_OK){
			goto failed;
		}

		conf->names->wc_tail = (ngx_hash_wildcard_t *) hash.hash;
	}

	ngx_destroy_pool(ha.temp_pool);

#if (NGX_PCRE)

	//该配置没有正则，进行下一个的块的处理
	if(regex == 0){
		return NGX_OK;
	}
	conf->nregex = regex;
	conf->regex = ngx_palloc(cf->pool, regex * sizeof(ngx_http_apls_server_t));
	if(conf->regex == NULL)
	{
		return NGX_ERROR;
	}	

	i = 0;

	var = conf->limit_data.elts;
	for(s = 0; s < conf->limit_data.nelts; s++)
	{
		if(var[s].regex){
			conf->regex[i++] = var[s];	
		}
	}
#endif
	//该块处理结束，继续处理下一个
	return NGX_OK;

failed:
	ngx_destroy_pool(ha.temp_pool);

	return NGX_ERROR;
}

static int ngx_libc_cdecl
ngx_http_apls_dns_wildcards(const void *one, const void *two)
{
	ngx_hash_key_t  *first, *second;

	first = (ngx_hash_key_t *) one;
	second = (ngx_hash_key_t *) two;

	return ngx_dns_strcmp(first->key.data, second->key.data);
}

static void *
ngx_http_apls_create_loc_conf(ngx_conf_t *cf)
{
	 ngx_http_apls_loc_conf_t  *conf;
	 conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_apls_loc_conf_t));
	 if(conf == NULL)
	 {
	 	return NULL;
	 }
		
	 if(ngx_array_init(&conf->limit_data,cf->pool,8,
				 	sizeof(ngx_http_apls_server_t))
			 != NGX_OK)
	 {
		return NULL;		 
	 }


	conf->names = ngx_pcalloc(cf->pool,sizeof(ngx_hash_combined_t));
	if(conf->names == NULL){
		return NULL;
	}

	 return conf;
}

static char *
ngx_http_apls_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_apls_loc_conf_t  *prev = parent;
	ngx_http_apls_loc_conf_t  *conf = child;

	if(conf->ls_key.data == NULL && conf->ls_key.len == 0 && conf->limit_data.nelts == 0)
	{
		conf->ls_key = prev->ls_key;
		conf->limit_data = prev->limit_data;
		conf->names = prev->names;
#if(NGX_PCRE)
		conf->nregex = prev->nregex;
		conf->regex = prev->regex;
#endif
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_apls_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	//hash prev loc_conf
	if(loc_conf && (ngx_http_apls_hash(cf, loc_conf) != NGX_OK))
	{
		loc_conf = NULL;
		return NGX_ERROR;
	}


	loc_conf = NULL;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_apls_handler;

	return NGX_OK;
}
