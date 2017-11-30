
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_dnion_variables_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_dnion_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_parent_response_time_variable(ngx_http_request_t *r, 
		ngx_http_variable_value_t *v, uintptr_t data);
		
static ngx_int_t ngx_http_response_time_variable(ngx_http_request_t *r, 
		ngx_http_variable_value_t *v, uintptr_t data);
		
static ngx_int_t ngx_http_request_error_variable(ngx_http_request_t *r, 
		ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_response_first_byte_time_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_response_body_first_byte_time_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

//static ngx_int_t ngx_http_dnion_variables_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_dnion_variables_write_filter(ngx_http_request_t *r, off_t bsent);
		
typedef struct {
	ngx_flag_t	dnion_variables_flag;
}ngx_http_dnion_variables_loc_conf_t;

typedef struct {
	ngx_msec_t	response_first_byte_time;
    ngx_flag_t  not_get_response_first;
    ngx_msec_t  response_body_first_byte_time;
    ngx_flag_t  not_get_response_body_first;
}ngx_http_dnion_variable_first_response_time_ctx_t;

static ngx_command_t  ngx_http_dnion_variables_commands[] = {

      ngx_null_command
};


static ngx_http_module_t  ngx_http_dnion_variables_module_ctx = {
    ngx_http_dnion_add_variables,       /* preconfiguration */
    ngx_http_dnion_variables_init,      /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,         /* create location configuration */
    NULL           /* merge location configuration */
};


ngx_module_t  ngx_http_dnion_variables_module = {
    NGX_MODULE_V1,
    &ngx_http_dnion_variables_module_ctx,         /* module context */
    ngx_http_dnion_variables_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_write_filter_pt    ngx_http_next_write_filter;

static ngx_http_variable_t  ngx_http_add_variables[] = {
	
    { ngx_string("parent_response_time"), NULL, ngx_http_parent_response_time_variable,
		0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
		
    { ngx_string("response_time"), NULL, ngx_http_response_time_variable,
		0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("request_error"), NULL, ngx_http_request_error_variable,
		0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("response_first_byte_time"), NULL, ngx_http_response_first_byte_time_variable,
		0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("response_body_first_byte_time"), NULL, ngx_http_response_body_first_byte_time_variable,
		0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_dnion_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_add_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t 
ngx_http_parent_response_time_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_msec_int_t              ms;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

	for ( ;; ) {
        if (state[i].status) {

            ms = state[i].response_time - state[i].header_time;
            ms = ngx_max(ms, 0);
            p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';
			if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_response_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;

    len = NGX_TIME_T_LEN + 4 + 2;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
	return NGX_ERROR;
    }
		
    v->data = p;
    p = ngx_sprintf(p, "%T.%03M", (time_t) r->send_response_time / 1000, (time_t) r->send_response_time % 1000);
    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_request_error_variable(ngx_http_request_t *r,
     ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    
    p = ngx_pnalloc(r->pool, 20);
    if (p == NULL) {
        return NGX_ERROR;
    }
		    
    v->data = p;
	if( r->upstream_error == 1) {
		p = ngx_sprintf(p, "upstream_abort");
	} else if((r->connection) && ( r->connection->read->eof == 1 || r->connection->error == 1 || r->connection->write->eof == 1)){
		p = ngx_sprintf(p, "client_abort");
	} else {
		p = ngx_sprintf(p, "-");
	}
    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
										  
    return NGX_OK;
}

static ngx_int_t ngx_http_response_first_byte_time_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *p;
    size_t len;
    ngx_http_dnion_variable_first_response_time_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_dnion_variables_module);
    if (ctx == NULL)
        return NGX_ERROR;
    if(ctx->not_get_response_first!=1)
    {
        return NGX_ERROR;
    }

    len = NGX_TIME_T_LEN + 4 + 2;

    p = ngx_pcalloc(r->pool, len);
    if (p == NULL) {
	    return NGX_ERROR;
    }
    v->data=p;
    p = ngx_sprintf(p, "%T.%03M", (time_t) ctx->response_first_byte_time / 1000, (time_t) ctx->response_first_byte_time % 1000);
    v->len = p - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t ngx_http_response_body_first_byte_time_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *p;
    size_t len;
    ngx_http_dnion_variable_first_response_time_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_dnion_variables_module);
    if (ctx == NULL)
        return NGX_ERROR;
    if(ctx->not_get_response_body_first!=1)
    {
        return NGX_ERROR;
    }

    len = NGX_TIME_T_LEN + 4 + 2;

    p = ngx_pcalloc(r->pool, len);
    if (p == NULL) {
	    return NGX_ERROR;
    }

    v->data=p;
    p = ngx_sprintf(p, "%T.%03M", (time_t) ctx->response_body_first_byte_time / 1000, (time_t) ctx->response_body_first_byte_time % 1000);
    v->len = p - v->data; 
    v->valid = 1; 
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t ngx_http_dnion_variables_write_filter(ngx_http_request_t *r, off_t bsent)
{
    ngx_time_t *tp;
    ngx_http_dnion_variable_first_response_time_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r,ngx_http_dnion_variables_module);
    if(ctx == NULL)
    {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dnion_variable_first_response_time_ctx_t));
        if (ctx == NULL)
        {
            return NGX_DECLINED;
        }

        ctx->response_first_byte_time=0;
        ctx->response_body_first_byte_time=0;
        ctx->not_get_response_first=0;
        ctx->not_get_response_body_first=0;
        ngx_http_set_ctx(r, ctx, ngx_http_dnion_variables_module);
    }

    tp = ngx_timeofday();

    if(ctx->not_get_response_first == 0)
    {
        if(r->connection->sent > 0)
        {
		    ctx->response_first_byte_time = (ngx_msec_int_t)((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
            ctx->not_get_response_first=1;
        }
    }

    if(ctx->not_get_response_body_first == 0)
    {
        if(r->connection->sent > 0 && r->header_size > 0)
        {
            if((r->connection->sent - r->header_size) > 0)
            {
                ctx->response_body_first_byte_time = (ngx_msec_int_t)((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
                ctx->not_get_response_body_first=1;
            }
        }
    }

    if(ngx_http_next_write_filter)
    {   
        return ngx_http_next_write_filter(r,bsent);
    }

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_dnion_variables_init(ngx_conf_t *cf)
{
    ngx_http_next_write_filter = ngx_http_top_write_filter;
    ngx_http_top_write_filter = ngx_http_dnion_variables_write_filter;

    return NGX_OK;
}

