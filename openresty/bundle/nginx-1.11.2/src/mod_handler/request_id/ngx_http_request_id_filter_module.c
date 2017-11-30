#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <uuid/uuid.h>

static ngx_int_t ngx_http_request_id_add_variables(ngx_conf_t *cf);
//static ngx_int_t ngx_http_request_id_variable(ngx_http_request_t *r,ngx_http_variable_value_t *v, uintptr_t data);
//static void ngx_http_set_request_id(ngx_http_request_t *r,ngx_http_variable_value_t *v,ngx_str_t request_id);
static ngx_int_t ngx_http_request_hop_variable(ngx_http_request_t *r,ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_set_request_hop(ngx_http_request_t *r,ngx_http_variable_value_t *v,ngx_str_t request_hop);

//static ngx_str_t ngx_http_request_id_name=ngx_string("request_id");
static ngx_str_t ngx_http_request_hop_name=ngx_string("request_hop");

static ngx_http_module_t ngx_http_request_id_filter_module_ctx = {
    ngx_http_request_id_add_variables,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

ngx_module_t ngx_http_request_id_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_request_id_filter_module_ctx,
    NULL,
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

static ngx_int_t
ngx_http_request_id_add_variables(ngx_conf_t *cf)
{
    //ngx_http_variable_t  *request_id;
    ngx_http_variable_t  *request_hop;

    //request_id = ngx_http_add_variable(cf, &ngx_http_request_id_name, 0);
    //if (request_id == NULL) {
    //    return NGX_ERROR;
    //}
    
    request_hop = ngx_http_add_variable(cf, &ngx_http_request_hop_name, 0);
    if (request_hop == NULL) {
        return NGX_ERROR;
    }

    //request_id->get_handler = ngx_http_request_id_variable;
    request_hop->get_handler = ngx_http_request_hop_variable;

    return NGX_OK;
}
/*
static ngx_int_t
ngx_http_request_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{

    ngx_list_part_t *part;
    part=&r->headers_in.headers.part;
    ngx_uint_t i;
    ngx_table_elt_t *h;
    uuid_t uuid;
    ngx_str_t  str_uuid;

    while(part != NULL){
        i=part->nelts;
        h=part->elts;

        while(i-- > 0){
            if(ngx_strncasecmp(h[i].key.data,(u_char*)"X-Request-ID",h[i].key.len)==0){
                ngx_http_set_request_id(r,v,h[i].value);
                return NGX_OK;
               }
         }
       
       part=part->next;
    }

    //create UUID
    str_uuid.len=36;  //the length of UUID is 36 (include -)
    str_uuid.data=ngx_pcalloc(r->pool, 36);
    uuid_generate(uuid);
    uuid_unparse(uuid, (char*)str_uuid.data);

    u_char* index_str=ngx_strlchr(str_uuid.data,str_uuid.data+str_uuid.len,'-');

    while(index_str !=NULL)
     {
        ngx_memcpy(index_str,index_str+1,str_uuid.data+str_uuid.len-index_str-1);
        ngx_memzero(str_uuid.data+str_uuid.len-1,1);
        str_uuid.len--;
        index_str=ngx_strlchr(str_uuid.data,str_uuid.data+str_uuid.len,'-');
    }
    
    ngx_http_set_request_id(r,v,str_uuid);
    return NGX_OK;
}

static void ngx_http_set_request_id(ngx_http_request_t *r,ngx_http_variable_value_t *v,ngx_str_t input)
{	
    v->len = input.len;
    v->data = input.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
}
*/

static ngx_int_t
ngx_http_request_hop_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{

    ngx_list_part_t *part;
    part=&r->headers_in.headers.part;
    ngx_uint_t i;
    ngx_table_elt_t *h;

    while(part != NULL){
        i=part->nelts;
        h=part->elts;

        while(i-- > 0){
            if(ngx_strncasecmp(h[i].key.data,(u_char*)"X-Request-HOP",h[i].key.len)==0){
                ngx_http_set_request_hop(r,v,h[i].value);
                return NGX_OK;
               }
         }
       
       part=part->next;
    }

    //create HOP
    ngx_str_t input;
    input.len=1;
    input.data=ngx_pcalloc(r->pool, input.len);
    ngx_memcpy(input.data,"1",1);

    v->len = input.len;
    v->data = input.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
  
   return NGX_OK;
}

static void ngx_http_set_request_hop(ngx_http_request_t *r,ngx_http_variable_value_t *v,ngx_str_t input)
{
	u_char	*last;
    ngx_str_t temp;
    ngx_str_null(&temp);

    ngx_int_t index_int=ngx_atoi(input.data,(size_t)(input.len));
    index_int++;

    temp.len=3;
    temp.data=ngx_pcalloc(r->pool, temp.len);
    last = ngx_sprintf(temp.data,"%d",(int)index_int);
	temp.len = last - temp.data;   
 
    v->len = temp.len;
    v->data = temp.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
}
