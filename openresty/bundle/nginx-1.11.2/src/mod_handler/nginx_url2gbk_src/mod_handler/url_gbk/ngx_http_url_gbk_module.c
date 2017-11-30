
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <iconv.h> 

enum
{
    URL_GBKENCODING = 1,
    URL_UTF8_ENCODING,
};
static int is_utf8_or_gbk(const unsigned char *str, int size);

static ngx_int_t ngx_http_url_gbk_init(ngx_conf_t *cf);
typedef struct {
    ngx_flag_t   on_off;
} ngx_http_url_gbk_loc_conf_t;


static void *ngx_http_url_gbk_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_url_gbk_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t  ngx_http_url_gbk_commands[] = {

    { ngx_string("url_gbk"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_url_gbk_loc_conf_t, on_off),
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_url_gbk_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_url_gbk_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_url_gbk_create_loc_conf,       /* create location configuration */
    ngx_http_url_gbk_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_url_gbk_module = {
    NGX_MODULE_V1,
    &ngx_http_url_gbk_module_ctx,          /* module context */
    ngx_http_url_gbk_commands,             /* module directives */
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

static inline void ngx_uri_gbk2utf8(ngx_http_request_t *r)
{
    iconv_t id;
    size_t inlen, outlen, len_backup;
    char *outp, *inp, *p_backup;


    /* inbuf inbytes */
    inp = p_backup = (char*)r->uri.data;
    inlen = r->uri.len;

    /* outbuf outbytes */
    outlen = len_backup = inlen * 3 / 2;
    outp = ngx_palloc(r->pool, outlen);
    if(outp == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate utf8 uri");
        return;
    }

    /* 更新uri内存地址 */
    r->uri.data = (u_char*)outp;

    id = iconv_open("utf-8","gb2312");
    if(id == (iconv_t)-1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "url_gbk iconv_open failed");
        return;
    }


    /* inp+ inlen-  outp+ outlen-, 初始outlen - 结束outlen 才是转换之后的数据长度 */
    if(iconv(id,&inp,&inlen,&outp,&outlen) == (size_t)-1)
    {
        r->uri.data = (u_char*)p_backup;        /* 转换失败 恢复uri的以前的地址 */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to convert gb2312 to utf-8");
        return;
    }
    /* 设置uri的真实长度 */
    r->uri.len = len_backup - outlen;

    iconv_close(id);
}

static ngx_int_t
ngx_http_url_gbk_handler(ngx_http_request_t *r)
{
    ngx_http_url_gbk_loc_conf_t *ulcf;
    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_url_gbk_module);

    if(ulcf->on_off == 0)
        return NGX_OK;

    if(is_utf8_or_gbk(r->uri.data, r->uri.len) == URL_GBKENCODING)
        ngx_uri_gbk2utf8(r);
    
    return NGX_OK;
}


static ngx_int_t
ngx_http_url_gbk_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_url_gbk_handler;

    return NGX_OK;
}


static void *
ngx_http_url_gbk_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_url_gbk_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_url_gbk_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }


    conf->on_off = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_url_gbk_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_url_gbk_loc_conf_t  *prev = parent;
    ngx_http_url_gbk_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->on_off, prev->on_off, 0);
    return NGX_CONF_OK;
}



/*
 * utf-8编码的判断格式如下：
1字节 0xxxxxxx
2字节 110xxxxx 10xxxxxx
3字节 1110xxxx 10xxxxxx 10xxxxxx
4字节 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
5字节 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
6字节 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
返回值大于0是utf8的size，0为不是utf8
*/
static inline int utf8_size(const unsigned char *str)
{
    /* utf8有1-6字节 */
    if((*str >> 7) == 0)
        return 1;

    if(((*str >> 6) & 0x1)== 0)
        return 0;
    int i;
    for(i = 5; i >= 1; i--)
    {
        if(((*str >> i) & 0x1) == 0)
            break;
    }
    if(i == 0)
        return 0;
    return 7 - i;
}
static inline int utf8_check(const unsigned char *str, int utf8_size)
{
    str++;
    int i;
    for(i = 0; i < utf8_size - 1; i++)
    {
        if((*str >> 6) != 2)
            return 0;
        str++;
    }
    return 1;
}
/*
 * gbk英文和utf8 ascii相同,1字节
 * http://www.cnblogs.com/feichexia/archive/2012/11/22/Encoding.html
 gbk  高字节：0x81~0xFE 低字节：0x40~0x7E 0x80~0xFE（即排除了xx7F）
*/ 
static inline int is_gbk2(const unsigned char *str)
{
    if(str[0] >= 0x81 && str[0] <= 0xfe 
            && str[1] >= 0x40 && str[1] <=0xfe && str[1] != 0x7f )
        return 1;
    return 0;
}

static int is_utf8_or_gbk(const unsigned char *str, int size)
{
    static int i = 0;
    i++;
    const unsigned char *end = str + size;
    while(str < end)
    {
        int utf8_size_v;
        utf8_size_v = utf8_size(str);
        if(utf8_size_v == 1)
        {
            str++;
            continue;
        }
        if(utf8_size_v > 0)
        {
            if(utf8_size_v != 3)            /* 仅考虑汉字 */
                return URL_GBKENCODING;

            /* utf8可能误判断 */
            if(str + utf8_size_v <= end)
            {
                if(utf8_check(str, utf8_size_v))
                {
                    if(!is_gbk2(str))
                        return URL_UTF8_ENCODING;
                    str += utf8_size_v;
                   // maybe_utf8 = 1;
                    continue;
                }
            }
        }
        /* gbk */
        return URL_GBKENCODING;
    }
    if(str > end)
        return URL_GBKENCODING;
    /* 可能是utf8, 也可能是gbk */
    return URL_UTF8_ENCODING;
}


