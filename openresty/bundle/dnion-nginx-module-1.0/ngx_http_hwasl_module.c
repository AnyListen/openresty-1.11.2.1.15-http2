#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

//#include <utime.h>

typedef struct
{
    ngx_str_t chkl_name;
    time_t asl_chkl_timeout;
} ngx_http_hwasl_chkl_t;

typedef struct
{
    ngx_str_t keyt_name;
    time_t keyt_start_time;
    time_t keyt_end_time;

} ngx_http_hwasl_keyt_t;

typedef struct
{
    ngx_array_t *keyt_array;

    time_t max_session_duration;

    ngx_flag_t asl_switch_flag;
    ngx_flag_t asl_switch_level1_flag;
    ngx_flag_t asl_switch_level2_flag;

    //ngx_http_hwasl_chkl_t *chk_l1;
    //ngx_http_hwasl_chkl_t *chk_l2;
    //ngx_http_hwasl_chkl_t *chk_l5;
    time_t asl_chkl1_timeout;
    time_t asl_chkl2_timeout;
    time_t asl_chkl5_timeout;

} ngx_http_hwasl_loc_conf_t;

typedef struct
{
    ngx_str_t user_ip;
    time_t timestamp_rise;
    ngx_str_t content_id;
    ngx_str_t chk_level;

    ngx_flag_t is_retry;

    time_t keyt_time_select;
    ngx_flag_t utc;

    ngx_str_t keyt_str;

    ngx_str_t decrypt_str;

    ngx_int_t file_type;

    ngx_str_t content_in_uri;

    ngx_str_t seek_start_time;
    ngx_str_t seek_end_time;
    ngx_flag_t playseek;

} ngx_http_hwasl_asl_t;

typedef struct
{
    ngx_str_t header_to_ats_keyt;
    ngx_str_t header_to_ats_encrypt_string;
} ngx_http_hwasl_ctx_t;

static ngx_int_t ngx_http_hwasl_add_header_value_to_ats(ngx_conf_t *cf);
static ngx_int_t ngx_http_hwasl_encrypt_string_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_hwasl_keyt_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_hwasl_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hwasl_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_conf_hwasl_chkl_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_hwasl_keyt_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_conf_str_to_time(time_t *timestamp, ngx_str_t time_str);
static ngx_int_t ngx_http_get_urldecode_info(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info, ngx_str_t *accountinfo);
static ngx_int_t ngx_http_get_keyt(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info, ngx_str_t *accountinfo);
static ngx_int_t ngx_http_decrypt(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info);
static ngx_int_t ngx_http_get_keyts_info_from_keyts(ngx_http_request_t *r, ngx_str_t decrypt_str, ngx_http_hwasl_asl_t *asl_info);
static ngx_int_t ngx_http_get_retry(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info);
static ngx_int_t ngx_http_get_file_type(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info);
static ngx_int_t ngx_http_get_content_in_path(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info);
static ngx_int_t ngx_http_get_playseek(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info);
static ngx_int_t ngx_http_aes256_decode(ngx_http_request_t *r, ngx_str_t keyt_str, ngx_str_t in_str, ngx_str_t *decrypt_str);
static ngx_int_t ngx_http_hwasl_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_hwasl_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hwasl_do(ngx_http_request_t *r);
static ngx_int_t ngx_http_hwasl_ini_asl_info(ngx_http_hwasl_asl_t *asl_info);
static void ngx_unescape_uri_patched(u_char **dst, u_char **src, size_t size, ngx_uint_t type);

static ngx_command_t ngx_http_hwasl_commands[] = {
    {ngx_string("hwasl_chklevel_timeout"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE3,
     ngx_conf_hwasl_chkl_value,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("max_session_duration"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_hwasl_loc_conf_t, max_session_duration),
     NULL},

    {ngx_string("keyt_info"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
     ngx_conf_hwasl_keyt_value,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("asl_switch_flag"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_hwasl_loc_conf_t, asl_switch_flag),
     NULL},

    {ngx_string("asl_switch_level2_flag"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_hwasl_loc_conf_t, asl_switch_level1_flag),
     NULL},

    {ngx_string("asl_switch_slice_flag"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_hwasl_loc_conf_t, asl_switch_level2_flag),
     NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_hwasl_module_ctx = {
    ngx_http_hwasl_add_header_value_to_ats,
    ngx_http_hwasl_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_hwasl_create_loc_conf, /* create location configuration */
    ngx_http_hwasl_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_hwasl_module = {
    NGX_MODULE_V1,
    &ngx_http_hwasl_module_ctx, /* module context */
    ngx_http_hwasl_commands,    /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    NULL,                       /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_variable_t ngx_http_hwasl_add_variable[] = {

    {ngx_string("asl_encrypt_string_to_ats"), NULL, ngx_http_hwasl_encrypt_string_variable,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("asl_key_to_ats"), NULL, ngx_http_hwasl_keyt_variable,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_null_string, NULL, NULL, 0, 0, 0}};

static ngx_int_t ngx_http_hwasl_handler(ngx_http_request_t *r)
{

    ngx_http_hwasl_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_hwasl_module);

    //ngx_str_t f = ngx_string("request_filename");
    //ngx_http_variable_value_t *a = ngx_http_get_variable(r, &f, ngx_hash_key_lc(f.data, f.len));

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uri:%V args:%V unparsed_uri:%V exten:%V", &(r->uri), &(r->args), &(r->unparsed_uri), &(r->exten));

    if (conf->asl_switch_flag == 0 || r != r->main || r->dnion_request == 1)
    {
        return NGX_DECLINED;
    }

    return ngx_http_hwasl_do(r);
}

static void *ngx_http_hwasl_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hwasl_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hwasl_loc_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->max_session_duration = NGX_CONF_UNSET;
    conf->asl_switch_flag = NGX_CONF_UNSET;
    conf->asl_switch_level1_flag = NGX_CONF_UNSET;
    conf->asl_switch_level2_flag = NGX_CONF_UNSET;
    conf->keyt_array = NGX_CONF_UNSET_PTR;
    //conf->chk_l1 = NGX_CONF_UNSET_PTR;
    //conf->chk_l2 = NGX_CONF_UNSET_PTR;
    //conf->chk_l5 = NGX_CONF_UNSET_PTR;
    conf->asl_chkl1_timeout = NGX_CONF_UNSET;
    conf->asl_chkl2_timeout = NGX_CONF_UNSET;
    conf->asl_chkl5_timeout = NGX_CONF_UNSET;

    return conf;
}

static char *ngx_http_hwasl_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hwasl_loc_conf_t *prev = parent;
    ngx_http_hwasl_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->asl_switch_flag, prev->asl_switch_flag, 0);
    ngx_conf_merge_value(conf->asl_switch_level1_flag, prev->asl_switch_level1_flag, 0);
    ngx_conf_merge_value(conf->asl_switch_level2_flag, prev->asl_switch_level2_flag, 0);
    ngx_conf_merge_value(conf->max_session_duration, prev->max_session_duration, (time_t)2 * 60 * 60);
    ngx_conf_merge_value(conf->asl_chkl1_timeout, prev->asl_chkl1_timeout, (time_t)5 * 60);
    ngx_conf_merge_value(conf->asl_chkl2_timeout, prev->asl_chkl2_timeout, (time_t)24 * 60 * 60);
    ngx_conf_merge_value(conf->asl_chkl5_timeout, prev->asl_chkl5_timeout, (time_t)5 * 60);
    ngx_conf_merge_ptr_value(conf->keyt_array, prev->keyt_array, NGX_CONF_UNSET_PTR);
    if (conf->asl_switch_flag == 1 && conf->keyt_array == NGX_CONF_UNSET_PTR)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "not find hwasl keyts.");
        return NGX_CONF_ERROR;
    }
    //ngx_conf_merge_ptr_value(conf->chk_l1,prev->chk_l1,NGX_CONF_UNSET_PTR);
    //ngx_conf_merge_ptr_value(conf->chk_l2,prev->chk_l2,NGX_CONF_UNSET_PTR);
    //ngx_conf_merge_ptr_value(conf->chk_l5,prev->chk_l5,NGX_CONF_UNSET_PTR);

    return NGX_CONF_OK;
}

static char *ngx_conf_hwasl_chkl_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_hwasl_loc_conf_t *m_conf = conf;
    ngx_uint_t i;
    ngx_str_t *values = cf->args->elts;
    //ngx_http_hwasl_chkl_t *chkl;
    u_char *pos, *p_e, *last;
    ngx_str_t s;
    ngx_int_t t;
    time_t *tim;
    /*
    if (m_conf->chk_l1 == NULL)
    {
        m_conf->chk_l1 = ngx_pcalloc(cf->pool, sizeof(ngx_http_hwasl_chkl_t));
        if (m_conf->chk_l1 == NULL)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (m_conf->chk_l2 == NULL)
    {
        m_conf->chk_l2 = ngx_pcalloc(cf->pool, sizeof(ngx_http_hwasl_chkl_t));
        if (m_conf->chk_l2 == NULL)
        {
            return NGX_CONF_ERROR;
        }
    }
    if (m_conf->chk_l5 == NULL)
    {
        m_conf->chk_l5 = ngx_pcalloc(cf->pool, sizeof(ngx_http_hwasl_chkl_t));
        if (m_conf->chk_l5 == NULL)
        {
            return NGX_CONF_ERROR;
        }
    }
*/
    for (i = 1; i < cf->args->nelts; i++)
    {
        if (ngx_strncmp(values[i].data, "1=", 2) == 0)
        {
            //chkl = m_conf->chk_l1;
            tim = &(m_conf->asl_chkl1_timeout);
        }
        else if (ngx_strncmp(values[i].data, "2=", 2) == 0)
        {
            //chkl = m_conf->chk_l2;
            tim = &(m_conf->asl_chkl2_timeout);
        }
        else if (ngx_strncmp(values[i].data, "5=", 2) == 0)
        {
            //chkl = m_conf->chk_l5;
            tim = &(m_conf->asl_chkl5_timeout);
        }
        else
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &values[i]);
            return NGX_CONF_ERROR;
        }
        pos = values[i].data;
        last = values[i].data + values[i].len;
        p_e = ngx_strlchr(pos, last, '=');
        //chkl->chkl_name.data = pos;
        //chkl->chkl_name.len = p_e - pos;
        ++p_e;
        s.data = p_e;
        s.len = last - p_e;
        t = ngx_parse_time(&s, 1);
        if (t == NGX_ERROR)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &values[i]);
            return NGX_CONF_ERROR;
        }
        //chkl->asl_chkl_timeout = t;
        *tim = t;
    }
    return NGX_CONF_OK;
}

static char *ngx_conf_hwasl_keyt_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_hwasl_loc_conf_t *m_conf = conf;
    ngx_str_t *values = cf->args->elts;

    ngx_http_hwasl_keyt_t *keyt;
    u_char *pos, *p_e, *last; //u_char *p_s;
    //ngx_uint_t i;
    ngx_str_t s;

    if (m_conf->keyt_array == NGX_CONF_UNSET_PTR)
    {
        m_conf->keyt_array = ngx_array_create(cf->pool, 4, sizeof(ngx_http_hwasl_keyt_t));
        if (m_conf->keyt_array == NULL)
        {
            return NGX_CONF_ERROR;
        }
    }

    keyt = ngx_array_push(m_conf->keyt_array);
    if (keyt == NULL)
    {
        return NGX_CONF_ERROR;
    }
    keyt->keyt_name = values[1];
    pos = values[2].data;
    last = values[2].data + values[2].len;
    p_e = ngx_strlchr(pos, last, '-');
    if (p_e == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &values[2]);
        return NGX_CONF_ERROR;
    }
    s.data = pos;
    s.len = p_e - pos;
    if (s.len <= 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &values[2]);
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_str_to_time(&(keyt->keyt_start_time), s) == NGX_ERROR)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &values[2]);
        return NGX_CONF_ERROR;
    }
    ++p_e;
    s.data = p_e;
    s.len = last - p_e;
    if (s.len <= 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &values[2]);
        return NGX_CONF_ERROR;
    }
    if (ngx_conf_str_to_time(&(keyt->keyt_end_time), s) == NGX_ERROR)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &values[2]);
        return NGX_CONF_ERROR;
    }

    u_char *a = ngx_pcalloc(cf->pool, 32);
    if (a == NULL)
        return NGX_CONF_ERROR;
    ngx_memset(a, '0', 32);
    ngx_memcpy(a, keyt->keyt_name.data, keyt->keyt_name.len);
    keyt->keyt_name.data = a;
    keyt->keyt_name.len = 32;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_get_file_type(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info)
{
    ngx_http_hwasl_loc_conf_t *aslcf;
    ngx_http_hwasl_asl_t *asl_conf_i = asl_info;
    ngx_int_t i;
    u_char *index_m = NULL;
    size_t index_l;

    if (r->exten.len == ngx_strlen("ts") && ngx_memcmp(r->exten.data, "ts", r->exten.len) == 0)
    {
        asl_conf_i->file_type = 3;
    }
    else if (r->exten.len == ngx_strlen("mp4") && ngx_memcmp(r->exten.data, "mp4", r->exten.len) == 0)
    {
        asl_conf_i->file_type = 3;
    }
    else if (r->exten.len == ngx_strlen("mpd") && ngx_memcmp(r->exten.data, "mpd", r->exten.len) == 0)
    {
        asl_conf_i->file_type = 1;
    }
    else if (r->exten.len == ngx_strlen("m3u8") && ngx_memcmp(r->exten.data, "m3u8", r->exten.len) == 0)
    {
        asl_conf_i->file_type = 2;
        for (i = r->uri.len - 1; i >= 0; i--)
        {
            if (r->uri.data[i] == '/')
            {
                index_m = &(r->uri.data[i]);
                index_l = r->uri.len - (index_m - r->uri.data);
                if (index_l == ngx_strlen("/index.m3u8") && ngx_memcmp(index_m, "/index.m3u8", ngx_strlen("/index.m3u8")) == 0)
                {
                    asl_conf_i->file_type = 1;
                    break;
                }
            }
        }
    }
    else
    {
        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "file type err");
        //return NGX_HTTP_FORBIDDEN;
        return NGX_DECLINED;
    }

    aslcf = ngx_http_get_module_loc_conf(r, ngx_http_hwasl_module);
    if (asl_conf_i->file_type == 2 && aslcf->asl_switch_level1_flag == 0)
    {
        return NGX_DECLINED;
    }
    if (asl_conf_i->file_type == 3 && aslcf->asl_switch_level2_flag == 0)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_get_content_in_path(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info)
{
    u_char *p_e, *last, *c_s, *p_l;
    ngx_int_t fond8 = 0;
    size_t l_tmp;
    ngx_http_hwasl_asl_t *asl_i = asl_info;

    last = r->uri.data + r->uri.len;
    p_e = r->uri.data;

    for (p_e = r->uri.data; p_e < last; p_e++)
    {
        if (*p_e == '/')
        {
            if (fond8 == 1)
            {
                ++p_e;
                if (p_e < last)
                {
                    c_s = p_e;
                    fond8 = 2;
                }
                else
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get content_id from uri err");
                    return NGX_HTTP_FORBIDDEN;
                }
            }
            else if (fond8 == 2)
            {
                asl_i->content_in_uri.data = c_s;
                asl_i->content_in_uri.len = p_e - c_s;
                return NGX_OK;
            }
            else if (fond8 == 0)
            {
                l_tmp = r->uri.len - (p_e - r->uri.data);
                if (l_tmp > ngx_strlen("/88888888/16/") && ngx_memcmp(p_e, "/88888888/16/", ngx_strlen("/88888888/16/")) == 0)
                {
                    p_e = p_e + ngx_strlen("/88888888/16/");
                    fond8 = 1;
                }
                else if (l_tmp > ngx_strlen("/88888888/224/") && ngx_memcmp(p_e, "/88888888/224/", ngx_strlen("/88888888/224/")) == 0)
                {
                    p_e = p_e + ngx_strlen("/88888888/224/");
                    p_l = ngx_strlchr(p_e, last, '/');
                    if (p_l == NULL)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get content_id from uri err");
                        return NGX_HTTP_FORBIDDEN;
                    }
                    asl_i->content_in_uri.data = p_e;
                    asl_i->content_in_uri.len = p_l - p_e;
                    return NGX_OK;
                }
                else
                {
                    continue;
                }
            }
            else
                continue;
        }
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get content_id from uri err");
    return NGX_HTTP_FORBIDDEN;
}

static ngx_int_t ngx_http_get_urldecode_info(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info, ngx_str_t *accountinfo)
{
    u_char *p_e, *last;
    u_char *src, *dst, *tmp;
    size_t src_len = 0;
    ngx_str_t guardenctype;
    ngx_str_null(&guardenctype);

    if (ngx_http_arg(r, (u_char *)"accountinfo", ngx_strlen("accountinfo"), accountinfo) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Not Find accountinfo");
        return NGX_HTTP_FORBIDDEN;
    }
    if (accountinfo->len <= 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Not Find accountinfo");
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_http_arg(r, (u_char *)"GuardEncType", ngx_strlen("GuardEncType"), &guardenctype) == NGX_OK)
    {
        if (guardenctype.len == 1 && ngx_memcmp(guardenctype.data, "1", guardenctype.len) == 0)
        {
            //pos = accountinfo.data;
            last = accountinfo->data + accountinfo->len;
            src = accountinfo->data;
            p_e = ngx_strlchr(src, last, ':');
            if (p_e == NULL)
            {
                p_e = ngx_strlchr(src, last, ',');
                if (p_e == NULL)
                    return NGX_HTTP_FORBIDDEN;
            }
            src_len = p_e - src;
            dst = ngx_pcalloc(r->pool, accountinfo->len);
            if (dst == NULL)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            tmp = dst;
            ngx_unescape_uri_patched(&dst, &src, src_len, 0);
            if (src != accountinfo->data + src_len)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "set_unescape_uri: input accountinfo data not consumed completely");
                return NGX_HTTP_FORBIDDEN;
            }

            ngx_memcpy(dst, p_e, last - p_e);
            accountinfo->data = tmp;
            accountinfo->len = ngx_strlen(tmp);
        }
        else if (guardenctype.len == 1 && ngx_memcmp(guardenctype.data, "2", guardenctype.len) == 0)
        {
            src = accountinfo->data;
            src_len = accountinfo->len;
            dst = ngx_pcalloc(r->pool, accountinfo->len);
            if (dst == NULL)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            tmp = dst;
            ngx_unescape_uri_patched(&dst, &src, src_len, 0);
            if (src != accountinfo->data + src_len)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "set_unescape_uri: input accountinfo data not consumed completely");
                return NGX_HTTP_FORBIDDEN;
            }
            accountinfo->data = tmp;
            accountinfo->len = ngx_strlen(tmp);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "uri:%V account_dec:%V", &(r->uri), accountinfo);
    return NGX_OK;
}

static ngx_int_t ngx_http_get_retry(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info)
{
    ngx_http_hwasl_asl_t *asl_i = asl_info;
    ngx_str_t retry_str;
    ngx_str_null(&retry_str);
    asl_i->is_retry = 0;

    if (ngx_http_arg(r, (u_char *)"retry", ngx_strlen("retry"), &retry_str) == NGX_OK)
    {
        if (retry_str.len == 1 && ngx_memcmp(retry_str.data, "1", retry_str.len) == 0)
            asl_i->is_retry = 1;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_get_playseek(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info)
{
    ngx_http_hwasl_asl_t *asl_i = asl_info;
    ngx_str_t playseek_str;
    //ngx_str_t s;
    u_char *pos, *p_e, *last;
    ngx_str_null(&playseek_str);
    asl_i->playseek = 0;

    if (ngx_http_arg(r, (u_char *)"playseek", ngx_strlen("playseek"), &playseek_str) == NGX_OK)
    {
        if (playseek_str.len < 3 && asl_i->file_type == 1)
        {
            return NGX_HTTP_FORBIDDEN;
        }
        else
        {
            pos = playseek_str.data;
            last = playseek_str.data + playseek_str.len;
            p_e = ngx_strlchr(pos, last, '-');
            if (p_e == NULL)
            {
                return NGX_HTTP_FORBIDDEN;
            }
            asl_i->seek_start_time.data = playseek_str.data;
            asl_i->seek_start_time.len = p_e - pos;
            if (asl_i->seek_start_time.len <= 0)
                return NGX_HTTP_FORBIDDEN;

            /*if (ngx_conf_str_to_time(&(asl_i->seek_start_time), s) == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "playseek time err, playseek:%V", &playseek_str);
                return NGX_HTTP_FORBIDDEN;
            }*/
            asl_i->seek_end_time.data = ++p_e;
            asl_i->seek_end_time.len = last - p_e;
            if (asl_i->seek_end_time.len <= 0)
                return NGX_HTTP_FORBIDDEN;
            /*if (ngx_conf_str_to_time(&(asl_i->seek_end_time), s) == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "playseek time err, playseek:%V", &playseek_str);
                return NGX_HTTP_FORBIDDEN;
            }*/
            asl_i->playseek = 1;
        }
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_aes256_decode(ngx_http_request_t *r, ngx_str_t keyt_str, ngx_str_t in_str, ngx_str_t *decrypt_str)
{
    ngx_int_t len = 0;
    ngx_int_t out_len = 0;
    u_char *decrypt_data = ngx_pcalloc(r->pool, in_str.len + 32);
    //unsigned char *decrypt_data = (unsigned char *)calloc(in_len + 32, 1);
    if (decrypt_data == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_padding(&ctx, 16);
    EVP_DecryptInit_ex(&ctx, EVP_aes_256_ecb(), NULL, keyt_str.data, NULL);
    if (!EVP_DecryptUpdate(&ctx, decrypt_data, (int *)&out_len, in_str.data, in_str.len))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return NGX_HTTP_FORBIDDEN;
    }
    if (!EVP_DecryptFinal_ex(&ctx, decrypt_data + out_len, (int *)&len))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return NGX_HTTP_FORBIDDEN;
    }
    //*decrypt_len = out_len + len;
    EVP_CIPHER_CTX_cleanup(&ctx);
    decrypt_str->data = decrypt_data;
    decrypt_str->len = out_len + len;
    return NGX_OK;
}

static ngx_int_t ngx_http_decrypt(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info)
{
    ngx_http_hwasl_ctx_t *ctx;
    ngx_http_hwasl_loc_conf_t *aslcf;
    ngx_str_t src_account;
    ngx_str_t dst_account;
    ngx_str_t decrypt_str;
    ngx_uint_t i;
    ngx_http_hwasl_keyt_t *keyts_info;
    time_t asl_timeo;
    ngx_str_null(&dst_account);
    ngx_str_null(&src_account);
    ngx_str_null(&decrypt_str);
    src_account = asl_info->keyt_str;

    dst_account.data = ngx_pcalloc(r->pool, ngx_base64_decoded_length(src_account.len));
    if (dst_account.data == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_decode_base64(&dst_account, &src_account) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "base64 decode fail");
        return NGX_HTTP_FORBIDDEN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "keyts:%V uri:%V", &src_account, &(r->uri));

    aslcf = ngx_http_get_module_loc_conf(r, ngx_http_hwasl_module);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hwasl_ctx_t));
    if (ctx == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_hwasl_module);

    keyts_info = aslcf->keyt_array->elts;
    for (i = 0; i < aslcf->keyt_array->nelts; i++)
    {
        ngx_int_t rr = NGX_HTTP_FORBIDDEN;
        if (asl_info->keyt_time_select < keyts_info[i].keyt_start_time || asl_info->keyt_time_select > keyts_info[i].keyt_end_time)
        {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "keyt_name:%V uri:%V", &(keyts_info[i].keyt_name), &(r->uri));
        rr = ngx_http_aes256_decode(r, keyts_info[i].keyt_name, dst_account, &decrypt_str);
        if (rr != NGX_OK)
        {
            return rr;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "aes_decode:%V uri:%V", &decrypt_str, &(r->uri));

        if (ngx_http_get_keyts_info_from_keyts(r, decrypt_str, asl_info) != NGX_OK)
            return NGX_HTTP_FORBIDDEN;

        ctx->header_to_ats_encrypt_string = decrypt_str;
        ctx->header_to_ats_keyt = keyts_info[i].keyt_name;

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "user_ip:%V content_id:%V chk_level:%V timestamp_rise:%l uri:%V content_id_inpath:%V", &(asl_info->user_ip), &(asl_info->content_id), &(asl_info->chk_level), asl_info->timestamp_rise, &(r->uri), &(asl_info->content_in_uri));
        if (asl_info->playseek == 0 || asl_info->playseek == 1)
        {
            if (asl_info->playseek == 1 && asl_info->file_type != 1)
            {
                if (asl_info->content_id.len != asl_info->content_in_uri.len || ngx_memcmp(asl_info->content_id.data, asl_info->content_in_uri.data, asl_info->content_id.len) != 0)
                {
                    continue;
                }
                return NGX_OK;
            }

            if (asl_info->chk_level.len == 1 && (ngx_memcmp(asl_info->chk_level.data, "1", 1) == 0))
            {
                if (r->connection->addr_text.len != asl_info->user_ip.len || ngx_memcmp(asl_info->user_ip.data, r->connection->addr_text.data, asl_info->user_ip.len) != 0)
                {
                    continue;
                }
                if (asl_info->content_id.len != asl_info->content_in_uri.len || ngx_memcmp(asl_info->content_id.data, asl_info->content_in_uri.data, asl_info->content_id.len) != 0)
                {
                    continue;
                }
                if (asl_info->file_type == 1)
                {
                    if (asl_info->is_retry)
                        asl_timeo = ngx_max(aslcf->asl_chkl1_timeout, aslcf->max_session_duration);
                    else
                        asl_timeo = aslcf->asl_chkl1_timeout;
                    if (ngx_abs(asl_info->timestamp_rise - ngx_time()) >= asl_timeo)
                    {
                        continue;
                    }
                }
                return NGX_OK;
            }
            else if (asl_info->chk_level.len == 1 && (ngx_memcmp(asl_info->chk_level.data, "2", 1) == 0))
            {
                if (r->connection->addr_text.len != asl_info->user_ip.len || ngx_memcmp(asl_info->user_ip.data, r->connection->addr_text.data, asl_info->user_ip.len) != 0)
                {
                    continue;
                }
                if (asl_info->content_id.len != asl_info->content_in_uri.len || ngx_memcmp(asl_info->content_id.data, asl_info->content_in_uri.data, asl_info->content_id.len) != 0)
                {
                    continue;
                }
                if (asl_info->file_type == 1)
                {
                    if (asl_info->is_retry)
                        asl_timeo = ngx_max(aslcf->asl_chkl2_timeout, aslcf->max_session_duration);
                    else
                        asl_timeo = aslcf->asl_chkl2_timeout;
                    if (ngx_abs(asl_info->timestamp_rise - ngx_time()) >= asl_timeo)
                    {
                        continue;
                    }
                }
                return NGX_OK;
            }
            else if (asl_info->chk_level.len == 1 && (ngx_memcmp(asl_info->chk_level.data, "3", 1) == 0))
            {
                if (asl_info->content_id.len != asl_info->content_in_uri.len || ngx_memcmp(asl_info->content_id.data, asl_info->content_in_uri.data, asl_info->content_id.len) != 0)
                {
                    continue;
                }
                return NGX_OK;
            }
            else if (asl_info->chk_level.len == 1 && (ngx_memcmp(asl_info->chk_level.data, "5", 1) == 0))
            {
                if (asl_info->content_id.len != asl_info->content_in_uri.len || ngx_memcmp(asl_info->content_id.data, asl_info->content_in_uri.data, asl_info->content_id.len) != 0)
                {
                    continue;
                }
                if (asl_info->file_type == 1)
                {
                    if (asl_info->is_retry)
                        asl_timeo = ngx_max(aslcf->asl_chkl5_timeout, aslcf->max_session_duration);
                    else
                        asl_timeo = aslcf->asl_chkl5_timeout;
                    if (ngx_abs(asl_info->timestamp_rise - ngx_time()) >= asl_timeo)
                    {
                        continue;
                    }
                }
                return NGX_OK;
            }
            else
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "illegal request, account_decrypt:%V", &decrypt_str);
                return NGX_HTTP_FORBIDDEN;
            }
        }
        /*else
        {
            if (asl_info->content_id.len != asl_info->content_in_uri.len || ngx_memcmp(asl_info->content_id.data, asl_info->content_in_uri.data, asl_info->content_id.len) != 0)
            {
                continue;
            }
            return NGX_OK;
        }*/
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "illegal request, account_decrypt:%V", &decrypt_str);
    return NGX_HTTP_FORBIDDEN;
}

static ngx_int_t ngx_http_get_keyts_info_from_keyts(ngx_http_request_t *r, ngx_str_t decrypt_str, ngx_http_hwasl_asl_t *asl_info)
{
    u_char *pos, *last, *ip_s, *times_s, *contentid_s, *chkls_s, *seek_stime, *seek_etime;
    size_t ip_len, times_len, contentid_len, chkls_len, seek_stime_len, seek_etime_len;
    ngx_str_t time_tmp;
    //time_t time_seek;
    ngx_int_t fond = 0;
    ngx_http_hwasl_asl_t *hwasl_info = asl_info;

    last = decrypt_str.data + decrypt_str.len;
    for (pos = decrypt_str.data; pos < last; pos++)
    {
        if (*pos == '$')
        {
            ++fond;

            if (fond == 2)
            {
                pos++;

                if (pos < last)
                {
                    ip_s = pos;
                    if (*pos == '$')
                    {
                        pos--;
                    }
                }
                else
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "decrypt keyts err, account_decrypt:%V", &decrypt_str);
                    return NGX_HTTP_FORBIDDEN;
                }
            }
            if (fond == 3)
            {
                ip_len = pos - ip_s;
            }
            if (fond == 4)
            {
                pos++;
                if (pos < last)
                {
                    times_s = pos;
                    if (*pos == '$')
                    {
                        pos--;
                    }
                }
                else
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "content_id err, account_decrypt:%V", &decrypt_str);
                    return NGX_HTTP_FORBIDDEN;
                }
            }
            if (fond == 5)
            {
                times_len = pos - times_s;
                pos++;
                if (pos < last)
                {
                    contentid_s = pos;
                    if (*pos == '$')
                    {
                        pos--;
                    }
                }
                else
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "content_id err, account_decrypt:%V", &decrypt_str);
                    return NGX_HTTP_FORBIDDEN;
                }
            }
            if (fond == 6)
            {
                contentid_len = pos - contentid_s;

                pos++;
                if (pos < last)
                {
                    seek_stime = pos;
                    if (*pos == '$')
                    {
                        pos--;
                    }
                }
                else
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "seek_stime err, account_decrypt:%V", &decrypt_str);
                    return NGX_HTTP_FORBIDDEN;
                }
            }
            if (fond == 7)
            {
                seek_stime_len = pos - seek_stime;
                pos++;
                if (pos < last)
                {
                    seek_etime = pos;
                    if (*pos == '$')
                    {
                        pos--;
                    }
                }
                else
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "seek_etime err, account_decrypt:%V", &decrypt_str);
                    return NGX_HTTP_FORBIDDEN;
                }
            }
            if (fond == 8)
            {
                seek_etime_len = pos - seek_etime;
                pos++;
                if (pos < last)
                {
                    chkls_s = pos;
                    if (*pos == '$')
                    {
                        pos--;
                    }
                }
                else
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check level err, account_decrypt:%V", &decrypt_str);
                    return NGX_HTTP_FORBIDDEN;
                }
            }
            if (fond == 9)
            {
                chkls_len = pos - chkls_s;
                break;
            }
        }
    }

    if (fond == 9)
    {
        hwasl_info->user_ip.data = ip_s;
        hwasl_info->user_ip.len = ip_len;
        hwasl_info->content_id.data = contentid_s;
        hwasl_info->content_id.len = contentid_len;
        hwasl_info->chk_level.data = chkls_s;
        hwasl_info->chk_level.len = chkls_len;

        if (hwasl_info->playseek == 1 && hwasl_info->file_type == 1)
        {
            if (seek_stime_len != hwasl_info->seek_start_time.len || ngx_memcmp(hwasl_info->seek_start_time.data, seek_stime, seek_stime_len) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid seek_start_time in request, account_decrypt:%V", &decrypt_str);
                return NGX_HTTP_FORBIDDEN;
            }

            if (seek_etime_len != hwasl_info->seek_end_time.len || ngx_memcmp(hwasl_info->seek_end_time.data, seek_etime, seek_etime_len) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid seek_end_time in request, account_decrypt:%V", &decrypt_str);
                return NGX_HTTP_FORBIDDEN;
            }

            /*
            time_tmp.data = seek_stime;
            time_tmp.len = seek_stime_len;
            time_seek = 0;

            if (ngx_conf_str_to_time(&time_seek, time_tmp) == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid seek_start_time in request, account_decrypt:%V", &decrypt_str);
                return NGX_HTTP_FORBIDDEN;
            }
            if (time_seek != hwasl_info->seek_start_time)
                return NGX_HTTP_FORBIDDEN;
            time_tmp.data = seek_etime;
            time_tmp.len = seek_etime_len;
            time_seek = 0;
            if (ngx_conf_str_to_time(&time_seek, time_tmp) == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid seek_end_time in request, account_decrypt:%V", &decrypt_str);
                return NGX_HTTP_FORBIDDEN;
            }
            if (time_seek != hwasl_info->seek_end_time)
                return NGX_HTTP_FORBIDDEN;*/
        }

        time_tmp.data = times_s;
        time_tmp.len = times_len;
        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "decrypt user_ip:%V content_id:%V chk_level:%V timest:%V uri:%V", &(hwasl_info->user_ip), &(hwasl_info->content_id), &(hwasl_info->chk_level), &time_tmp, &(r->uri));

        if (hwasl_info->content_id.len <= 0 || hwasl_info->chk_level.len <= 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "content_id err or chk_level err, account_decrypt:%V", &decrypt_str);
            return NGX_HTTP_FORBIDDEN;
        }

        if (hwasl_info->chk_level.len == 1 && (ngx_memcmp(hwasl_info->chk_level.data, "1", 1) == 0 || ngx_memcmp(hwasl_info->chk_level.data, "2", 1) == 0 || ngx_memcmp(hwasl_info->chk_level.data, "5", 1) == 0))
        {
            if (ngx_conf_str_to_time(&(hwasl_info->timestamp_rise), time_tmp) == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid time in request, account_decrypt:%V", &decrypt_str);
                return NGX_HTTP_FORBIDDEN;
            }
            if (hwasl_info->utc == 1)
                hwasl_info->timestamp_rise = hwasl_info->timestamp_rise + 8 * 60 * 60;
            return NGX_OK;
        }
        else if (hwasl_info->chk_level.len == 1 && ngx_memcmp(hwasl_info->chk_level.data, "3", 1) == 0)
        {
            hwasl_info->timestamp_rise = -1;
            return NGX_OK;
        }
        else
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "chk_level err, account_decrypt:%V", &decrypt_str);
            return NGX_HTTP_FORBIDDEN;
        }
    }
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "decrypt keyts err, account_decrypt:%V", &decrypt_str);
    return NGX_HTTP_FORBIDDEN;
}

static ngx_int_t ngx_http_get_keyt(ngx_http_request_t *r, ngx_http_hwasl_asl_t *asl_info, ngx_str_t *accountinfo)
{
    ngx_http_hwasl_asl_t *asl_k_conf = asl_info;
    time_t time_sel;
    ngx_flag_t utc;
    u_char *p_e, *last, *p_e2, *src;
    ngx_str_t timest_str;

    ngx_str_t src_account;
    ngx_str_t dst_account;

    ngx_str_null(&dst_account);
    ngx_str_null(&src_account);

    last = accountinfo->data + accountinfo->len;
    src = accountinfo->data;

    src_account.data = accountinfo->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "before find keyts info uri:%V account_urldecode:%V", &(r->uri), accountinfo);

    p_e = ngx_strlchr(src, last, ':');
    if (p_e == NULL)
    {
        time_sel = ngx_time();
        utc = 0;
        p_e = ngx_strlchr(src, last, ',');
        if (p_e == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get keyts err, accountinfo:%V", accountinfo);
            return NGX_HTTP_FORBIDDEN;
        }
        src_account.len = p_e - accountinfo->data;
    }
    else
    {
        src_account.len = p_e - accountinfo->data;
        ++p_e;
        if (p_e < last)
        {
            p_e2 = ngx_strlchr(p_e, last, ':');
            if (p_e2 == NULL)
            {
                p_e2 = ngx_strlchr(p_e, last, ',');
                if (p_e2 == NULL)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get keyts err, accountinfo:%V", accountinfo);
                    return NGX_HTTP_FORBIDDEN;
                }
                else
                {
                    utc = 0;
                }
            }
            else
            {
                if (last - p_e2 > 3 && ngx_memcmp(p_e2, ":UTC", 3) == 0)
                {
                    utc = 1;
                }
                else
                    utc = 0;
            }
            timest_str.data = p_e;
            timest_str.len = p_e2 - p_e;
            if (ngx_conf_str_to_time(&time_sel, timest_str) == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get keyts err, invalid Keyts_Select_Time param, accountinfo:%V", accountinfo);
                return NGX_HTTP_FORBIDDEN;
            }
        }
        else
        {
            time_sel = ngx_time();
            utc = 0;
        }
    }

    if (time_sel <= 0 || src_account.len <= 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get keyts err, accountinfo:%V", accountinfo);
        return NGX_HTTP_FORBIDDEN;
    }
    if (utc == 1)
        time_sel += 8 * 3600;

    asl_k_conf->utc = utc;
    asl_k_conf->keyt_time_select = time_sel;
    asl_k_conf->keyt_str = src_account;
    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "keyts info uri:%V keyts_str:%V time_select:%l utc:%i", &(r->uri), &(asl_k_conf->keyt_str), asl_k_conf->keyt_time_select, asl_k_conf->utc);

    /*
    dst_account.data = ngx_pcalloc(r->pool, ngx_base64_decoded_length(src_account->len));
    if (dst_account.data == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_decode_base64(&dst_account, &src_account) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "base64 decode fail.");
        return NGX_HTTP_FORBIDDEN;
    }
*/
    return NGX_OK;
}

static ngx_int_t ngx_http_hwasl_ini_asl_info(ngx_http_hwasl_asl_t *asl_info)
{
    ngx_str_null(&asl_info->user_ip);
    asl_info->timestamp_rise = -1;
    ngx_str_null(&asl_info->content_id);
    ngx_str_null(&asl_info->chk_level);
    asl_info->is_retry = 0;
    asl_info->keyt_time_select = -1;
    asl_info->utc = 0;
    ngx_str_null(&asl_info->keyt_str);
    ngx_str_null(&asl_info->decrypt_str);
    asl_info->file_type = 1;
    ngx_str_null(&asl_info->content_in_uri);
    //asl_info->seek_start_time = -1;
    //asl_info->seek_end_time = -1;
    asl_info->playseek = 0;
    ngx_str_null(&asl_info->seek_start_time);
    ngx_str_null(&asl_info->seek_end_time);

    return NGX_OK;
}

static ngx_int_t ngx_http_hwasl_do(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_str_t accountinfo;
    ngx_http_hwasl_asl_t asl_info;
    ngx_http_hwasl_ini_asl_info(&asl_info);
    ngx_str_null(&accountinfo);

    rc = ngx_http_get_file_type(r, &asl_info);
    if (rc != NGX_OK)
        return rc;

    rc = ngx_http_get_content_in_path(r, &asl_info);
    if (rc != NGX_OK)
        return rc;

    rc = ngx_http_get_retry(r, &asl_info);
    if (rc != NGX_OK)
        return rc;

    rc = ngx_http_get_playseek(r, &asl_info);
    if (rc != NGX_OK)
        return rc;

    rc = ngx_http_get_urldecode_info(r, &asl_info, &accountinfo);
    if (rc != NGX_OK)
        return rc;

    rc = ngx_http_get_keyt(r, &asl_info, &accountinfo);
    if (rc != NGX_OK)
        return rc;

    rc = ngx_http_decrypt(r, &asl_info);
    if (rc != NGX_OK)
        return rc;

    return NGX_DECLINED;
}

static ngx_int_t ngx_conf_str_to_time(time_t *timestamp, ngx_str_t time_str)
{
    if (time_str.len != 14)
        return NGX_ERROR;
    time_t l_time = 0;
    struct tm timeptr;
    u_char *name, *last;
    name = malloc(time_str.len + 1);
    if (name == NULL)
        return NGX_ERROR;
    last = ngx_cpymem(name, time_str.data, time_str.len);
    last = '\0';
    if (strptime((const char *)name, "%Y%m%d%H%M%S", &timeptr))
    {
        l_time = mktime(&timeptr);
        if (l_time > 0)
        {
            *timestamp = l_time;
            free(name);
            return NGX_OK;
        }
    }
    free(name);
    return NGX_ERROR;
}

static ngx_int_t ngx_http_hwasl_encrypt_string_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_hwasl_ctx_t *ctx;
    size_t len;
    uintptr_t escape;
    u_char *p;
    ctx = ngx_http_get_module_ctx(r, ngx_http_hwasl_module);
    if (ctx == NULL)
        return NGX_ERROR;
    escape = 2 * ngx_escape_uri(NULL, ctx->header_to_ats_encrypt_string.data, ctx->header_to_ats_encrypt_string.len, NGX_ESCAPE_URI_COMPONENT);
    len = escape + ctx->header_to_ats_encrypt_string.len;
    p = ngx_pcalloc(r->pool, len);
    if (p == NULL)
        return NGX_ERROR;
    v->data = p;
    if (escape == 0)
    {
        ngx_memcpy(p, ctx->header_to_ats_encrypt_string.data, len);
    }
    else
    {
        ngx_escape_uri(p, ctx->header_to_ats_encrypt_string.data, ctx->header_to_ats_encrypt_string.len, NGX_ESCAPE_URI_COMPONENT);
    }

    ngx_log_debug3(NGX_LOG_ERR, r->connection->log, 0, "header escape_len:%i keyts_header:%s src:%V", escape, v->data, &(ctx->header_to_ats_encrypt_string));

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_http_hwasl_keyt_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_hwasl_ctx_t *ctx;
    size_t len;
    uintptr_t escape;
    u_char *p;
    ctx = ngx_http_get_module_ctx(r, ngx_http_hwasl_module);
    if (ctx == NULL)
        return NGX_ERROR;
    escape = 2 * ngx_escape_uri(NULL, ctx->header_to_ats_keyt.data, ctx->header_to_ats_keyt.len, NGX_ESCAPE_URI_COMPONENT);
    len = escape + ctx->header_to_ats_keyt.len;
    p = ngx_pcalloc(r->pool, len);
    if (p == NULL)
        return NGX_ERROR;
    v->data = p;
    if (escape == 0)
    {
        ngx_memcpy(p, ctx->header_to_ats_keyt.data, len);
    }
    else
    {
        ngx_escape_uri(p, ctx->header_to_ats_keyt.data, ctx->header_to_ats_keyt.len, NGX_ESCAPE_URI_COMPONENT);
    }

    ngx_log_debug3(NGX_LOG_ERR, r->connection->log, 0, "header escape_len:%i keyts_header:%s src:%V", escape, v->data, &(ctx->header_to_ats_keyt));

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_http_hwasl_add_header_value_to_ats(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;
    for (v = ngx_http_hwasl_add_variable; v->name.len; v++)
    {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL)
        {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_hwasl_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_hwasl_handler;

    return NGX_OK;
}

static void ngx_unescape_uri_patched(u_char **dst, u_char **src, size_t size, ngx_uint_t type)
{
    u_char *d, *s, ch, c, decoded;
    enum
    {
        sw_usual = 0,
        sw_quoted,
        sw_quoted_second
    } state;

    d = *dst;
    s = *src;

    state = 0;
    decoded = 0;

    while (size--)
    {

        ch = *s++;

        switch (state)
        {
        case sw_usual:
            if (ch == '?' && (type & (NGX_UNESCAPE_URI | NGX_UNESCAPE_REDIRECT)))
            {
                *d++ = ch;
                goto done;
            }

            if (ch == '%')
            {
                state = sw_quoted;
                break;
            }

            if (ch == '+')
            {
                *d++ = ' ';
                break;
            }

            *d++ = ch;
            break;

        case sw_quoted:

            if (ch >= '0' && ch <= '9')
            {
                decoded = (u_char)(ch - '0');
                state = sw_quoted_second;
                break;
            }

            c = (u_char)(ch | 0x20);
            if (c >= 'a' && c <= 'f')
            {
                decoded = (u_char)(c - 'a' + 10);
                state = sw_quoted_second;
                break;
            }

            /* the invalid quoted character */

            state = sw_usual;

            *d++ = ch;

            break;

        case sw_quoted_second:

            state = sw_usual;

            if (ch >= '0' && ch <= '9')
            {
                ch = (u_char)((decoded << 4) + ch - '0');

                if (type & NGX_UNESCAPE_REDIRECT)
                {
                    if (ch > '%' && ch < 0x7f)
                    {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%';
                    *d++ = *(s - 2);
                    *d++ = *(s - 1);

                    break;
                }

                *d++ = ch;

                break;
            }

            c = (u_char)(ch | 0x20);
            if (c >= 'a' && c <= 'f')
            {
                ch = (u_char)((decoded << 4) + c - 'a' + 10);

                if (type & NGX_UNESCAPE_URI)
                {
                    if (ch == '?')
                    {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                if (type & NGX_UNESCAPE_REDIRECT)
                {
                    if (ch == '?')
                    {
                        *d++ = ch;
                        goto done;
                    }

                    if (ch > '%' && ch < 0x7f)
                    {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%';
                    *d++ = *(s - 2);
                    *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }

            /* the invalid quoted character */

            break;
        }
    }

done:

    *dst = d;
    *src = s;
}