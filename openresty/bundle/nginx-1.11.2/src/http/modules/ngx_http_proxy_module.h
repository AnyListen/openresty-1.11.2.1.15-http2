
#ifndef _NGX_HTTP_PROXY_H_INCLUDED_
#define _NGX_HTTP_PROXY_H_INCLUDED_
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_str_t *ngx_http_proxy_get_upstream(ngx_http_request_t *r);

#endif /* _NGX_HTTP_PROXY_H_INCLUDED_ */
