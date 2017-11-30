
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>  
#include "express_verify.h"

#define DEFAULT_STR_VALUE ""
#define DEFAULT_INT_VALUE 0

#define SK_HEADER_ERR "ERR"

typedef struct {
	ngx_str_t         ua_name;
	ngx_regex_t      *ua_regex;
} ngx_http_qqmusic_filter_ua_format;

typedef struct {
	ngx_flag_t        enable;
	ngx_array_t      *uas;
} ngx_http_qqmusic_filter_loc_conf_t;

typedef struct {
	ngx_int_t vkey;
	ngx_int_t guid;
	ngx_int_t uin;
	ngx_int_t fromtag;
} ngx_http_qqmusic_filter_var_index;


static ngx_http_qqmusic_filter_var_index ngx_http_args_index;
static ngx_http_qqmusic_filter_var_index ngx_http_cookies_index;

static ngx_str_t dnion_ua = ngx_string("Dnion-UA-");

static ngx_str_t ngx_http_arg_vkey = ngx_string("arg_vkey");
static ngx_str_t ngx_http_arg_guid = ngx_string("arg_guid");
static ngx_str_t ngx_http_arg_uin = ngx_string("arg_uin");
static ngx_str_t ngx_http_arg_fromtag = ngx_string("arg_fromtag");

static ngx_str_t ngx_http_cookie_vkey = ngx_string("cookie_qqmusic_vkey");
static ngx_str_t ngx_http_cookie_guid = ngx_string("cookie_qqmusic_guid");
static ngx_str_t ngx_http_cookie_uin = ngx_string("cookie_qqmusic_uin");
static ngx_str_t ngx_http_cookie_fromtag = ngx_string("cookie_qqmusic_fromtag");

static ngx_int_t ngx_http_qqmusic_filter_add_sk_header(ngx_http_request_t *r, const char *value, size_t len);
static unsigned long long ngx_http_qqmusic_filter_var_value(ngx_http_request_t *r, ngx_int_t index1, ngx_int_t index2, ngx_flag_t str);
static ngx_int_t ngx_http_qqmusic_filter_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_qqmusic_filter_access(ngx_http_request_t *r);
static ngx_int_t ngx_http_qqmusic_filter_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_qqmusic_filter_init(ngx_conf_t *cf);
static char *ngx_http_qqmusic_filter_ua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_qqmusic_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_qqmusic_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t  ngx_http_qqmusic_filter_commands[] = {

    { ngx_string("qqmusic_ua"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_qqmusic_filter_ua,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("qqmusic_filter"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_qqmusic_filter_loc_conf_t, enable),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_qqmusic_filter_module_ctx = {
    ngx_http_qqmusic_filter_add_variables,         /* preconfiguration */
    ngx_http_qqmusic_filter_init,                  /* postconfiguration */

    NULL,                                          /* create main configuration */
    NULL,                                          /* init main configuration */

    NULL,                                          /* create server configuration */
    NULL,                                          /* merge server configuration */

    ngx_http_qqmusic_filter_create_loc_conf,       /* create location configuration */
    ngx_http_qqmusic_filter_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_qqmusic_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_qqmusic_filter_module_ctx,           /* module context */
    ngx_http_qqmusic_filter_commands,              /* module directives */
    NGX_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    NULL,                                          /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t 
ngx_http_qqmusic_filter_add_variables(ngx_conf_t *cf)
{
	ngx_int_t                            n;

	n = ngx_http_get_variable_index(cf, &ngx_http_arg_vkey);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }
    ngx_http_args_index.vkey = n;

    n = ngx_http_get_variable_index(cf, &ngx_http_arg_guid);
    if (n == NGX_ERROR) {
    	return NGX_ERROR;
    }
    ngx_http_args_index.guid = n;

    n = ngx_http_get_variable_index(cf, &ngx_http_arg_uin);
    if (n == NGX_ERROR) {
    	return NGX_ERROR;
    }
    ngx_http_args_index.uin = n;

    n = ngx_http_get_variable_index(cf, &ngx_http_arg_fromtag);
    if (n == NGX_ERROR) {
    	return NGX_ERROR;
    }
    ngx_http_args_index.fromtag = n;

    n = ngx_http_get_variable_index(cf, &ngx_http_cookie_vkey);
    if (n == NGX_ERROR) {
    	return NGX_ERROR;
    }
    ngx_http_cookies_index.vkey = n;        

    n = ngx_http_get_variable_index(cf, &ngx_http_cookie_guid);
    if (n == NGX_ERROR) {
    	return NGX_ERROR;
    }
    ngx_http_cookies_index.guid = n;

    n = ngx_http_get_variable_index(cf, &ngx_http_cookie_uin);
    if (n == NGX_ERROR) {
    	return NGX_ERROR;
    }
    ngx_http_cookies_index.uin = n;

    n = ngx_http_get_variable_index(cf, &ngx_http_cookie_fromtag);
    if (n == NGX_ERROR) {
    	return NGX_ERROR;
    }
    ngx_http_cookies_index.fromtag = n;

    return NGX_OK;
}

static unsigned long long 
ngx_http_qqmusic_filter_var_value(ngx_http_request_t *r, ngx_int_t index1, ngx_int_t index2, ngx_flag_t is_str)
{
	ngx_http_variable_value_t  *value;

	value = ngx_http_get_indexed_variable(r, index1);
	
	if (value == NULL || value->not_found) {
		value = ngx_http_get_indexed_variable(r, index2);
		if (value == NULL || value->not_found) {
			return is_str ? (unsigned long long)DEFAULT_STR_VALUE : DEFAULT_INT_VALUE;
		} else {
			return is_str ? (unsigned long long)value->data : strtoull((const char *)value->data, NULL, 10);
		}
	}

	return is_str ? (unsigned long long)value->data : strtoull((const char *)value->data, NULL, 10);
}

static ngx_int_t
ngx_http_qqmusic_filter_add_sk_header(ngx_http_request_t *r, const char *value, size_t len)
{
    u_char                     *header;
    ngx_table_elt_t            *sk;

    sk = ngx_list_push(&r->headers_out.headers);
    if (sk == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    header = ngx_pnalloc(r->pool, len);
    if (header == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    (void)ngx_cpymem(header, value, len);

    sk->hash = 1;
    ngx_str_set(&sk->key, "Server-Check");
    sk->value.data = header;
    sk->value.len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_qqmusic_filter_access(ngx_http_request_t *r)
{
	static int                  magic_num = 2013;
	int                         fromtag;
	const char                 *vkey, *guid, *filename;
	unsigned long long          uin;
	int                         v_res, c_res;
    char                        pEncryptBuf[32];

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_HTTP_FORBIDDEN;
    }

    filename = (const char *)r->uri.data + 1;

    vkey = (const char *)ngx_http_qqmusic_filter_var_value(r, ngx_http_args_index.vkey, ngx_http_cookies_index.vkey, 1);
    guid = (const char *)ngx_http_qqmusic_filter_var_value(r, ngx_http_args_index.guid, ngx_http_cookies_index.guid, 1);

    uin = ngx_http_qqmusic_filter_var_value(r, ngx_http_args_index.uin, ngx_http_cookies_index.uin, 0);

    fromtag = (int)ngx_http_qqmusic_filter_var_value(r, ngx_http_args_index.fromtag, ngx_http_cookies_index.fromtag, 0);

    c_res = qqmusic_create_server_key(
        guid,
        pEncryptBuf,
        32
    );

	v_res = qqmusic_verify_express_key(
		vkey, 
		strlen(vkey), 
		magic_num, 
		guid, 
		filename, 
		uin, 
		fromtag
	);

    if (c_res) {
        ngx_http_qqmusic_filter_add_sk_header(r, SK_HEADER_ERR, sizeof(SK_HEADER_ERR) - 1);
        return NGX_HTTP_FORBIDDEN;
    }

    if (v_res) {
        ngx_http_qqmusic_filter_add_sk_header(r, pEncryptBuf, 32);
        return NGX_HTTP_FORBIDDEN;
    }

    ngx_http_qqmusic_filter_add_sk_header(r, pEncryptBuf, 32);

	return NGX_DECLINED;
}

static ngx_int_t
ngx_http_qqmusic_filter_handler(ngx_http_request_t *r)
{
	u_char                              *ua;
	size_t                               len = 0;
	ngx_int_t                            n;
    ngx_uint_t                           i;
	ngx_http_qqmusic_filter_loc_conf_t  *qflcf;
	ngx_http_qqmusic_filter_ua_format   *uas;

	qflcf = ngx_http_get_module_loc_conf(r, ngx_http_qqmusic_filter_module);

	if (!qflcf->enable) {
		return NGX_DECLINED;
	}

	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_POST))) {
        return NGX_DECLINED;
    }

    if (r->headers_in.user_agent == NULL && qflcf->uas != NULL && qflcf->uas->nelts != 0) {
    	return NGX_DECLINED;
    }

    if (r->headers_in.user_agent != NULL) {
    	ua = r->headers_in.user_agent->value.data;
    	len = r->headers_in.user_agent->value.len;
    
    	if (len == dnion_ua.len && !ngx_strncmp(ua, dnion_ua.data, len)) {
    		return NGX_DECLINED;
    	}
    }

    if (qflcf->uas == NULL || qflcf->uas->nelts == 0) {
    	return ngx_http_qqmusic_filter_access(r);
    }

    if (len == 0) {
    	return NGX_DECLINED;
    }

    uas = qflcf->uas->elts;

    for (i = 0; i < qflcf->uas->nelts; i++) {
    	n = ngx_regex_exec(uas[i].ua_regex, &r->headers_in.user_agent->value, NULL, 0);

    	if (n >= 0) {
    		return ngx_http_qqmusic_filter_access(r);
    	}

    	if (n != NGX_REGEX_NO_MATCHED) {
    		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                	ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
            	    n, &r->uri, &uas[i].ua_name);    		
    	}
    } 

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_qqmusic_filter_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_qqmusic_filter_handler;

    return NGX_OK;
}

static char *
ngx_http_qqmusic_filter_ua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t                           *value;
	ngx_regex_compile_t                  rc;
	ngx_http_qqmusic_filter_loc_conf_t  *qflcf = conf;
	ngx_http_qqmusic_filter_ua_format   *uf;
	u_char                               errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;

    if (qflcf->uas == NULL) {
        qflcf->uas = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_qqmusic_filter_ua_format));
        if (qflcf->uas == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_CONF_ERROR;
    }

    uf = ngx_array_push(qflcf->uas);
    if (uf == NULL) {
    	return NGX_CONF_ERROR;
    }

    uf->ua_name = value[1];
    uf->ua_regex = rc.regex;

    return NGX_CONF_OK;
}


static void *
ngx_http_qqmusic_filter_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_qqmusic_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_qqmusic_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_qqmusic_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_qqmusic_filter_loc_conf_t *prev = parent;
    ngx_http_qqmusic_filter_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->uas == NULL && prev->uas != NULL) {
    	conf->uas = prev->uas;
    }

    return NGX_CONF_OK;
}



