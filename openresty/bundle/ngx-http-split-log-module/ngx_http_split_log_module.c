#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;  
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


extern ngx_int_t ngx_http_log_handler(ngx_http_request_t *r);

typedef struct {
    ngx_flag_t log_split;
    time_t     log_split_time;
} ngx_http_split_log_loc_conf_t;

typedef struct {
    ngx_flag_t first;
    ngx_uint_t last_sent;
    time_t     last_time;
} ngx_http_split_log_filter_ctx_t;

static ngx_int_t ngx_http_split_log_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_split_log_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_split_log_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static void *ngx_http_split_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_split_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_split_log_request_handler(ngx_http_request_t *r);

static ngx_command_t  ngx_http_split_log_commands[] = {
    {
        ngx_string("log_split"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_split_log_loc_conf_t, log_split),
        NULL
    },

    { 
        ngx_string("log_split_time"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_sec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_split_log_loc_conf_t, log_split_time),
        NULL 
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_split_log_module_ctx = {
    NULL,                                        /* preconfiguration */
    ngx_http_split_log_filter_init,              /* postconfiguration */

    NULL,                                        /* create main configuration */
    NULL,                                        /* init main configuration */

    NULL,                                        /* create server configuration */
    NULL,                                        /* merge server configuration */

    ngx_http_split_log_create_loc_conf,          /* create location configuration */
    ngx_http_split_log_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_split_log_module = {
    NGX_MODULE_V1,
    &ngx_http_split_log_module_ctx,          /* module context */
    ngx_http_split_log_commands,             /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};



static ngx_int_t  
ngx_http_split_log_filter_init(ngx_conf_t *cf)  
{  
    ngx_http_next_header_filter = ngx_http_top_header_filter;  
    ngx_http_top_header_filter = ngx_http_split_log_header_filter;  
  
    ngx_http_next_body_filter = ngx_http_top_body_filter;  
    ngx_http_top_body_filter = ngx_http_split_log_body_filter;

    ngx_http_log_request_handler = ngx_http_split_log_request_handler;
  
    return NGX_OK;  
}  

static ngx_int_t
ngx_http_split_log_header_filter(ngx_http_request_t *r)
{
    ngx_http_split_log_filter_ctx_t  *ctx;
    ngx_http_split_log_loc_conf_t    *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_split_log_module);

    if (!slcf->log_split) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_split_log_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->first     = 1;
    ctx->last_sent = r->connection->sent;
    ctx->last_time = r->start_sec;

    ngx_http_set_ctx(r, ctx, ngx_http_split_log_module);

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_split_log_request_handler(ngx_http_request_t *r)
{
    ngx_http_split_log_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_split_log_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    r->connection->sent = r->connection->sent - ctx->last_sent;

    return NGX_OK;
}

static ngx_int_t
ngx_http_split_log_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                         rc;
    ngx_int_t                         sent;
    ngx_time_t                       *tp;
    ngx_http_split_log_filter_ctx_t  *ctx;
    ngx_http_split_log_loc_conf_t    *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_split_log_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_split_log_module);

    tp = ngx_timeofday();

    if (tp->sec - ctx->last_time >= slcf->log_split_time) {
        sent = r->connection->sent;
        if (!ctx->first) {
            r->connection->sent = r->connection->sent - ctx->last_sent;
        }

        rc = ngx_http_log_handler(r);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "log to access log file failed");
        }

        r->connection->sent = sent;
        r->header_size = 0;

        ctx->first     = 0;
        ctx->last_time = tp->sec;
        ctx->last_sent = r->connection->sent;
    }

    return ngx_http_next_body_filter(r, in);
}

static void *
ngx_http_split_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_split_log_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_split_log_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->log_split = NGX_CONF_UNSET;
    conf->log_split_time = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_split_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_split_log_loc_conf_t *prev = parent;
    ngx_http_split_log_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->log_split, prev->log_split, 0);
    ngx_conf_merge_sec_value(conf->log_split_time, prev->log_split_time, 300);

    return NGX_CONF_OK;
}

