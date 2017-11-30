#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct{
	ngx_str_t		key;
	ngx_array_t		value;
	ngx_int_t		rate;
	time_t			time_begin;
	time_t			time_end;
}ngx_http_rhsvr_limit_param_t;

typedef struct{
	ngx_array_t						*domains;
	ngx_array_t						*param_data;
	ngx_array_t						*param_data_nokey;
	ngx_array_t						*param_data_notime;
}ngx_http_rhsvr_limit_conf_t;


static ngx_int_t ngx_http_rhsvr_limit_handler(ngx_http_request_t *r);
static char *ngx_http_rhsvr_limit_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_rhsvr_limit_param_nokey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_rhsvr_limit_param_notime(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void* ngx_http_rhsvr_limit_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_rhsvr_limit_merge_loc_conf(ngx_conf_t *cf,void *parent,void *child);
static ngx_int_t ngx_http_rhsvr_limit_init(ngx_conf_t *cf);
static char *ngx_http_rhsvr_limit_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_rhsvr_limit_commands[] = {

	{ ngx_string("limit_param"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE4,
	  ngx_http_rhsvr_limit_param,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL},

	{ ngx_string("limit_param_nokey"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
	  ngx_http_rhsvr_limit_param_nokey,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL},

	{ ngx_string("limit_param_notime"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
	  ngx_http_rhsvr_limit_param_notime,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL},

	{ ngx_string("limit_domains"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
	  ngx_http_rhsvr_limit_domain,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL},

	ngx_null_command
};


static ngx_http_module_t ngx_http_rhsvr_limit_module_ctx={

	NULL,									/* preconfiguration */
	ngx_http_rhsvr_limit_init,				/* postconfiguration */
	
	NULL,									/* create main configuration */
	NULL,									/* init main configuration */

	NULL,									/* create server configuration */
	NULL,									/* merge server configuration */

	ngx_http_rhsvr_limit_create_loc_conf,			/* create location configuration */
	ngx_http_rhsvr_limit_merge_loc_conf				/* merge location configuration */
};


ngx_module_t  ngx_http_rhsvr_limit_module = {
	NGX_MODULE_V1,
	&ngx_http_rhsvr_limit_module_ctx,		/* module context */
	ngx_http_rhsvr_limit_commands,			/* module directives */
	NGX_HTTP_MODULE,				/* module type */
	NULL,						/* init master */
	NULL,						/* init module */
	NULL,						/* init process */
	NULL,						/* init thread */
	NULL,						/* exit thread */
	NULL,						/* exit process */
	NULL,						/* exit master */
	NGX_MODULE_V1_PADDING					
};

static ngx_int_t ngx_http_rhsvr_limit_handler(ngx_http_request_t *r)
{
	ngx_flag_t	flag, domain_flag;
	ngx_uint_t	i, j;
	ngx_int_t	*value_data,args_data;
	ngx_str_t	args, *domain;
	time_t		sec;
	ngx_http_rhsvr_limit_param_t	*param;

	flag = 0;
	domain_flag = 1;

	ngx_http_rhsvr_limit_conf_t	*conf = ngx_http_get_module_loc_conf(r,ngx_http_rhsvr_limit_module);


	if(conf->domains != NULL){
		domain = conf->domains->elts;
		for( i = 0; i < conf->domains->nelts; i++){
			if(r->headers_in.host->value.len == domain[i].len &&
					ngx_memcmp(r->headers_in.host->value.data, domain[i].data, domain[i].len) == 0 ) {
				break;
			}
		}

		if( i == conf->domains->nelts ) {
			domain_flag = 0;
		}
	}

	if( domain_flag == 0) {
		return NGX_DECLINED;
	}

	//param_data key=l value=10,20 time=11:00-12:00 rate=100k;
	if(conf->param_data->nelts != 0) 
	{
		param = conf->param_data->elts;

		for( i = 0; i < conf->param_data->nelts; i ++) {

			//key not in args
			if(ngx_http_arg(r, param[i].key.data, param[i].key.len, &args) != NGX_OK){
				continue;
			}
	
			args_data = ngx_atoi(args.data, args.len);
			if(args_data == NGX_ERROR) {
				return NGX_DECLINED;
			}

			value_data = param[i].value.elts;
			for( j = 0; j < param[i].value.nelts; j ++)
			{
				if(value_data[j] == args_data) {
					flag = 1;
					break;
				}
			}

			if(flag == 0){
				continue;
			}

			sec = ((r->start_sec + 8*60*60)/(24*60*60) ) * (24*60*60);

			if(((r->start_sec + 8*60*60)>= (sec + param[i].time_begin)) && 
							((r->start_sec + 8*60*60) <= (sec + param[i].time_end)))
			{
				r->limit_rate = param[i].rate;
				return NGX_DECLINED;
			}
		}
	}
	
	flag = 0;
	//param_data_notime key=l value=10,20 rate=100k;
	if(conf->param_data_notime->nelts != 0) {
		
		param = conf->param_data_notime->elts;

		for( i = 0; i < conf->param_data_notime->nelts; i ++) {

			//key not in arg
			if(ngx_http_arg(r, param[i].key.data, param[i].key.len, &args) != NGX_OK){
				continue;
			}
			
			args_data = ngx_atoi(args.data, args.len);
			if(args_data == NGX_ERROR) {
				return NGX_DECLINED;
			}

			value_data = param[i].value.elts;
			for( j = 0; j < param[i].value.nelts; j ++)
			{
				if(value_data[j] == args_data) {
					flag = 1;
					break;
				}
			}

			if(flag == 0){
				continue;
			}

			r->limit_rate = param[i].rate;
			
			return NGX_DECLINED;
			
		}
	}

	//param_data_nokey time=11:00-12:00 rate=100k;
	if(conf->param_data_nokey->nelts != 0) {

		param = conf->param_data_nokey->elts;

		for( i = 0; i < conf->param_data_nokey->nelts; i ++) {

			sec = ((r->start_sec + 8*60*60)/(24*60*60) ) * (24*60*60);

			if(((r->start_sec + 8*60*60)>= (sec + param[i].time_begin)) &&
							((r->start_sec + 8*60*60) <= (sec + param[i].time_end)))
			{
				r->limit_rate = param[i].rate;
				return NGX_DECLINED;
			}
		}
	}

	return NGX_DECLINED;
}

static char *ngx_http_rhsvr_limit_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	u_char				*p, *p1, *start, *last;
	ngx_uint_t			i;
	ngx_int_t			data;
	ngx_str_t			rate,*value;
	ngx_int_t			min,hour,*value_data;
	ngx_http_rhsvr_limit_param_t	*param;

	min = 0;
	hour = 0;

	ngx_http_rhsvr_limit_conf_t *rlcf = conf;
	value = cf->args->elts;

	param = ngx_array_push(rlcf->param_data);
	if(param == NULL){
		return NGX_CONF_ERROR;
	}

	if(ngx_array_init(&param->value, cf->pool, 10, sizeof(ngx_int_t)) != NGX_OK){
		return NGX_CONF_ERROR;
	}

	for(i = 1; i < cf->args->nelts; i++)
	{
		last = value[i].data + value[i].len;
		
		if (ngx_strncmp(value[i].data, "key=", 4) == 0)
		{
			param->key.data = value[i].data + 4;
			param->key.len = value[i].len - 4;
			
			continue;
		}

		if (ngx_strncmp(value[i].data, "value=", 6) == 0)
		{

			start = value[i].data + 6;
			p = (u_char *)ngx_strchr(start, ',');
			
			while(p){
				
				data = ngx_atoi(start, p-start);
				if(data == NGX_ERROR){
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"invalid value \"%V\"", &value[i]);

					return NGX_CONF_ERROR;
				}

				value_data = ngx_array_push(&param->value);

				*value_data = data;

				start = p + 1;

				if(start >= last) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"invalid value \"%V\"", &value[i]);

					return NGX_CONF_ERROR;
				}

				p = (u_char *)ngx_strchr(start, ',');
			}

			data = ngx_atoi(start,last-start);
			if(data == NGX_ERROR){
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"invalid value \"%V\"", &value[i]);

				return NGX_CONF_ERROR;
			}

			value_data = ngx_array_push(&param->value);

			*value_data = data;

			continue;
		}

		if (ngx_strncmp(value[i].data, "time=", 5) == 0)
		{
			start = value[i].data + 5;
			p = (u_char *)ngx_strchr(start, '-');
			
			if(p == NULL)
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
									"invalid value \"%V\"", &value[i]);

				return NGX_CONF_ERROR;
			}

			p1 = (u_char *)ngx_strnstr(start, ":", (p - start));
			if(p1 != NULL)
			{
				min = ngx_atoi(p1+1,p-(p1+1));
				if(min == NGX_ERROR)
				{
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"invalid value \"%V\"", &value[i]);
					return NGX_CONF_ERROR;
				}
			}
			else 
			{
				p1 = p;
				min = 0;
			}

			hour = ngx_atoi(start, (p1-start));
			if(hour == NGX_ERROR)
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"invalid value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}


			param->time_begin = hour*60*60 + min*60;


			//time_end
			start = p + 1;

			p1 = (u_char *)ngx_strnstr(start, ":", last - start);
			if(p1 != NULL)
			{
				min = ngx_atoi(p1+1,last-(p1+1));
				if(min == NGX_ERROR)
				{
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"invalid value \"%V\"", &value[i]);
					return NGX_CONF_ERROR;
				}
			}
			else 
			{
				p1 = last;
				min = 0;
			}

			hour = ngx_atoi(p+1, p1-(p+1));
			if(hour == NGX_ERROR)
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"invalid value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			param->time_end = hour*60*60 + min*60;

			continue;

		}

		if (ngx_strncmp(value[i].data, "rate=", 5) == 0){

			rate.data = value[i].data + 5;
			rate.len = value[i].len - 5;

			param->rate = ngx_parse_size(&rate);

			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"invalid parameter \"%V\"", &value[i]);
		return NGX_CONF_ERROR;

	}

	return NGX_CONF_OK;
}

static char *ngx_http_rhsvr_limit_param_nokey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	u_char                          *p, *p1, *start, *last;
	ngx_uint_t                      i;
	ngx_str_t                       rate,*value;
	ngx_int_t                       min,hour;
	ngx_http_rhsvr_limit_param_t    *param;

	ngx_http_rhsvr_limit_conf_t *rlcf = conf;
	value = cf->args->elts;

	param = ngx_array_push(rlcf->param_data_nokey);
	if(param == NULL){
		return NGX_CONF_ERROR;
	}

	if(ngx_array_init(&param->value, cf->pool, 10, sizeof(ngx_int_t)) != NGX_OK){
		return NGX_CONF_ERROR;
	}

	for(i = 1; i < cf->args->nelts; i++)
	{
		last = value[i].data + value[i].len;

		if (ngx_strncmp(value[i].data, "time=", 5) == 0)
		{
			start = value[i].data + 5;
			p = (u_char *)ngx_strchr(start, '-');

			if(p == NULL)
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                         "invalid value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			p1 = (u_char *)ngx_strnstr(start, ":", (p - start));
			if(p1 != NULL)
			{
				min = ngx_atoi(p1+1,p-(p1+1));
				if(min == NGX_ERROR)
				{
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
										"invalid value \"%V\"", &value[i]);
					return NGX_CONF_ERROR;
				}
			}
			else
			{
				p1 = p;
				min = 0;
			}

			hour = ngx_atoi(start, (p1-start));
			if(hour == NGX_ERROR)
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			param->time_begin = hour*60*60 + min*60;

			//time_end
			start = p + 1;

			p1 = (u_char *)ngx_strnstr(start, ":", last - start);
			if(p1 != NULL)
			{
				min = ngx_atoi(p1+1,last-(p1+1));
				if(min == NGX_ERROR)
				{
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"invalid value \"%V\"", &value[i]);
					return NGX_CONF_ERROR;
				}
			}
			else
			{
				p1 = last;
				min = 0;
			}

			hour = ngx_atoi(p+1, p1-(p+1));
			if(hour == NGX_ERROR)
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"invalid value \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
            }

            param->time_end = hour*60*60 + min*60;

            continue;
		}

		if (ngx_strncmp(value[i].data, "rate=", 5) == 0){

						rate.data = value[i].data + 5;
						rate.len = value[i].len - 5;

						param->rate = ngx_parse_size(&rate);
                        continue;
 		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                           "invalid parameter \"%V\"", &value[i]);
		return NGX_CONF_ERROR;
	}

	 return NGX_CONF_OK;
}

static char *ngx_http_rhsvr_limit_param_notime(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	u_char                          *p, *start, *last;
        ngx_uint_t                      i;
        ngx_int_t                       data;
        ngx_str_t                       rate,*value;
        ngx_int_t                       min,hour,*value_data;
        ngx_http_rhsvr_limit_param_t    *param;

	min = 0;
        hour = 0;

        ngx_http_rhsvr_limit_conf_t *rlcf = conf;
        value = cf->args->elts;

	param = ngx_array_push(rlcf->param_data_notime);
        if(param == NULL){
                return NGX_CONF_ERROR;
        }

        if(ngx_array_init(&param->value, cf->pool, 10, sizeof(ngx_int_t)) != NGX_OK){
                return NGX_CONF_ERROR;
        }

	for(i = 1; i < cf->args->nelts; i++)
	{
		last = value[i].data + value[i].len;

		if (ngx_strncmp(value[i].data, "key=", 4) == 0)
                {
                        param->key.data = value[i].data + 4;
                        param->key.len = value[i].len - 4;

                        continue;
                }

		if (ngx_strncmp(value[i].data, "value=", 6) == 0)
                {

                        start = value[i].data + 6;
                        p = (u_char *)ngx_strchr(start, ',');

                        while(p){

                                data = ngx_atoi(start, p-start);
                                if(data == NGX_ERROR){
                                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                                                "invalid value \"%V\"", &value[i]);

                                        return NGX_CONF_ERROR;
                                }

                                value_data = ngx_array_push(&param->value);

                                *value_data = data;

                                start = p + 1;

                                if(start >= last) {
                                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                                                "invalid value \"%V\"", &value[i]);

                                        return NGX_CONF_ERROR;
                                }

                                p = (u_char *)ngx_strchr(start, ',');
                        }

                        data = ngx_atoi(start,last-start);
                        if(data == NGX_ERROR){
                                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                                                "invalid value \"%V\"", &value[i]);

                                return NGX_CONF_ERROR;
                        }

                        value_data = ngx_array_push(&param->value);

                        *value_data = data;

			continue;
                }

		if (ngx_strncmp(value[i].data, "rate=", 5) == 0){

                        rate.data = value[i].data + 5;
                        rate.len = value[i].len - 5;

                        param->rate = ngx_parse_size(&rate);

                        continue;
                }

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                                                "invalid parameter \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *ngx_http_rhsvr_limit_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_uint_t		i;	
	ngx_str_t		*value,*domain;
	ngx_http_rhsvr_limit_conf_t		*rlcf = conf;
	
	value = cf->args->elts;

	if(rlcf->domains != NGX_CONF_UNSET_PTR)	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, " \"qqmusic_domains\" already existed");
		return NGX_CONF_ERROR;
	}

	rlcf->domains = ngx_array_create(cf->pool, 10, sizeof(ngx_str_t));
	if(rlcf->domains == NULL){
		return NGX_CONF_ERROR;
	}

	for( i = 1; i < cf->args->nelts; i++) {
		domain = ngx_array_push(rlcf->domains);
		if(domain == NULL) {
			return NGX_CONF_ERROR;
		}

		*domain = value[i];
	}

	return NGX_CONF_OK;	
}


static void* ngx_http_rhsvr_limit_create_loc_conf(ngx_conf_t *cf)
{

	ngx_http_rhsvr_limit_conf_t	*conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_rhsvr_limit_conf_t));
	if(conf == NULL) {
		return NULL;
	}

	conf->param_data = ngx_array_create(cf->pool, 10, sizeof(ngx_http_rhsvr_limit_param_t));
	if(conf->param_data == NULL){
		return NULL;
	}

	conf->param_data_nokey = ngx_array_create(cf->pool, 10, sizeof(ngx_http_rhsvr_limit_param_t));
	if(conf->param_data_nokey == NULL){
		return NULL;
	}

	conf->param_data_notime = ngx_array_create(cf->pool, 10, sizeof(ngx_http_rhsvr_limit_param_t));
	if(conf->param_data_notime == NULL){
		return NULL;
	}

	conf->domains = NGX_CONF_UNSET_PTR;

	return conf;
}

static char * ngx_http_rhsvr_limit_merge_loc_conf(ngx_conf_t *cf,void *parent,void *child)
{
	ngx_http_rhsvr_limit_conf_t	*prev = parent;
	ngx_http_rhsvr_limit_conf_t	*conf = child;

	if(conf->param_data->nelts == 0){
		conf->param_data = prev->param_data;
	}

	if(conf->param_data_nokey->nelts == 0){
		conf->param_data_nokey = prev->param_data_nokey;
	}
	
	if(conf->param_data_notime->nelts == 0){
		conf->param_data_notime = prev->param_data_notime;
	}

	ngx_conf_merge_ptr_value(conf->domains, prev->domains, NULL);
	
	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_rhsvr_limit_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	cmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if(h == NULL){
		return NGX_ERROR;
	}

	*h = ngx_http_rhsvr_limit_handler;

	return NGX_OK;
}
