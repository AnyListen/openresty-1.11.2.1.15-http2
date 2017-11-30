#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <net/if.h>

#include "ngx_http_gslb_check_module.h"

//view
typedef struct {
	ngx_str_t               name;
	ngx_array_t             servers;
	ngx_uint_t				server_index;
}ngx_http_view_t;

//named.conf
typedef struct {
	ngx_radix_tree_t                *ips;
	ngx_array_t                     *views;
	ngx_http_view_t                 *any_view;
	ngx_array_t						*mac_ip;
} ngx_http_mdns_loc_conf_t;

static ngx_int_t ngx_http_mdns_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_mdns_pre(ngx_conf_t *cf);
static void *ngx_http_mdns_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mdns_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_mdns_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_mdns_set_header(ngx_http_request_t *r, ngx_str_t *new_host, ngx_str_t *host, ngx_str_t *parsed_uri); 
static ngx_str_t *ngx_http_mdns_get_live_os(ngx_array_t *servers, ngx_uint_t *index);
static ngx_int_t ngx_http_mdns_conf_read_token(ngx_conf_t *cf); 

static char *ngx_http_mdns_named_conf_parse(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_mdns_named_conf_parse_file(ngx_conf_t *cf, ngx_radix_tree_t *tree, ngx_array_t *views, ngx_http_view_t **any_view);
static ngx_int_t ngx_http_mdns_get_ifreq(ngx_conf_t *cf, ngx_http_mdns_loc_conf_t *conf); 

static ngx_command_t  ngx_http_mdns_commands[] = {

	{ ngx_string("named_conf"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_http_mdns_named_conf_parse,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL},

	ngx_null_command
};

static ngx_http_module_t  ngx_http_mdns_module_ctx = {
	ngx_http_mdns_pre,                   /* preconfiguration */
	ngx_http_mdns_init,                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_mdns_create_loc_conf,       /* create location configuration */
	ngx_http_mdns_merge_loc_conf         /* merge location configuration */
};

#define NGX_CONF_BUFFER   4096

ngx_module_t  ngx_http_mdns_module = {
	NGX_MODULE_V1,
	&ngx_http_mdns_module_ctx,           /* module context */
	ngx_http_mdns_commands,              /* module directives */
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

static ngx_int_t
ngx_http_mdns_handler(ngx_http_request_t *r)
{
	uintptr_t			view_id;
	ngx_uint_t			i,j;
	ngx_http_view_t		*view, *pview;
	ngx_connection_t	*c;
	ngx_str_t			host, *ip;
	ngx_http_mdns_loc_conf_t	*conf;
	ngx_str_t			*vserver, *pserver;

	conf = ngx_http_get_module_loc_conf(r,ngx_http_mdns_module);

	if( r != r->main ){
		return NGX_DECLINED;
	}

	if(r->headers_in.user_agent != NULL) {
		if( (r->headers_in.user_agent->value.len == ngx_strlen("Dnion_Precache")) &&
			(ngx_memcmp(r->headers_in.user_agent->value.data, "Dnion_Precache", ngx_strlen("Dnion_Precache")) == 0)){
			r->dnion_request = 1;
			return NGX_DECLINED;
		}
	}

	if( r->gslb_dispatch || conf->ips == NULL ||  conf->views == NULL ) {
		return NGX_DECLINED;
	}

	c = r->connection;
	
	host = r->headers_in.server;

	//namad.conf exist
	if(conf->ips != NULL)
	{
		ip = conf->mac_ip->elts;
		view_id = ngx_radix32tree_find(conf->ips, ntohl(ngx_inet_addr(c->addr_text.data, c->addr_text.len)));
		if(view_id != (uintptr_t) -1) {
			pview = conf->views->elts;
			view = &pview[view_id];

			pserver = view->servers.elts;
			for(i = 0; i<view->servers.nelts; i++) 
			{
				for( j = 0; j < conf->mac_ip->nelts; j ++) {
					if( ip[j].len == pserver[i].len && ngx_strncmp(pserver[i].data, ip[j].data, ip[j].len) == 0) {
						break;
					}
				}
				if( j != conf->mac_ip->nelts ){
					break;
				}
			}

			if( i == view->servers.nelts) {
				//get a server by round robin
				vserver = ngx_http_mdns_get_live_os(&view->servers, &view->server_index);

				//get failed
				if(vserver == NULL) {
					return NGX_DECLINED;
				} else {
					//get sucessed
					if(ngx_http_mdns_set_header(r, vserver, &host, &r->unparsed_uri) != NGX_OK) {
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}
					//ngx_http_send_header(r);
					return NGX_HTTP_MOVED_TEMPORARILY;
				}
			}
		}
	}

	return NGX_DECLINED;
}


static ngx_int_t ngx_http_mdns_set_header(ngx_http_request_t *r, ngx_str_t *new_host, ngx_str_t *host, ngx_str_t *parsed_uri) 
{
	u_char			*last;
	ngx_str_t		uri;
	ngx_table_elt_t		*h;

	h = ngx_list_push(&r->headers_out.headers);
	if( h == NULL ){
		return NGX_ERROR;
	}
	
	//http:// + 1.1.1.1 +  /  + www.baidu.com + /a.jpg
	uri.len = ngx_strlen("http://") + new_host->len + 1 + host->len + parsed_uri->len;
	uri.data = ngx_palloc(r->pool, uri.len);
	if( uri.data == NULL ){
		return NGX_ERROR;
	}

	last = uri.data;
	last = ngx_copy( last, "http://", ngx_strlen("http://") );
	last = ngx_copy( last, new_host->data, new_host->len );
	*last++ = '/';
	last = ngx_copy( last, host->data, host->len );
	last = ngx_copy( last, parsed_uri->data, parsed_uri->len);

	h->value.len = uri.len;
	h->value.data = uri.data;

	h->hash = 1;
	ngx_str_set( &h->key, "Location");

	r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
	r->keepalive = 0;

	return NGX_OK;
}


static ngx_str_t *ngx_http_mdns_get_live_os(ngx_array_t *servers, ngx_uint_t *index)
{
	ngx_uint_t i;
	ngx_str_t	*ps, *server;
	ps = servers->elts;

	for(i = 0; i < servers->nelts; i++) {
		server = &ps[*index];
		(*index) ++;
		(*index) %= servers->nelts;

		if( !ngx_http_gslb_check_peer_down(ntohl(ngx_inet_addr(server->data, server->len)))) {
			break;
		}

	}

	if(i == servers->nelts) {
		return NULL;
	}

	return server;
}

static char *ngx_http_mdns_named_conf_parse(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mdns_loc_conf_t *mdcf = conf;

	///radix tree
	mdcf->ips = ngx_radix_tree_create(cf->pool,  -1);
	if(mdcf->ips == NULL) {
		return NGX_CONF_ERROR;
	}
	
	///views
	mdcf->views = ngx_array_create(cf->pool, 128, sizeof(ngx_http_view_t));
	if(mdcf->views == NULL) {
		return NGX_CONF_ERROR;
	}

	if(ngx_http_mdns_named_conf_parse_file(cf, mdcf->ips, mdcf->views, &mdcf->any_view) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}


static void *
ngx_http_mdns_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mdns_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mdns_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	return conf;
}

static char *
ngx_http_mdns_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mdns_loc_conf_t  *prev = parent;
	ngx_http_mdns_loc_conf_t  *conf = child;

	if(conf->ips == NULL) {
		conf->ips = prev->ips;
	}

	if(conf->views == NULL) {
		conf->views = prev->views;
	}

	if(conf->any_view == NULL) {
		conf->any_view = prev->any_view;
	}

	if(conf->mac_ip == NULL){
		conf->mac_ip = prev->mac_ip;
	}

	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_mdns_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_mdns_handler;

	return NGX_OK;
}



static ngx_int_t 
ngx_http_mdns_named_conf_parse_file(ngx_conf_t *cf, ngx_radix_tree_t *tree, ngx_array_t *views, ngx_http_view_t **any_view)
{
	u_char		*slash;
	u_char		*q;
	uint32_t	mask;
	ngx_int_t	mask_size;
	u_char		*last, *start, *end;
	in_addr_t	ip;
	ngx_fd_t	fd;
	ngx_str_t	*value;
	ngx_str_t	path;
	ngx_str_t	*server;
	ngx_buf_t	buf;
	ngx_int_t	rc;
	uintptr_t	view_index = -1;

	ngx_conf_file_t *prev;
	ngx_conf_file_t	*named_conf;
	
	ngx_http_view_t	*view;

	view = NULL;

    enum {
		parse_view = 0,
		parse_match_client,
    } type;

	type = parse_view;

	///named_conf
	named_conf = ngx_pcalloc(cf->pool, sizeof(ngx_conf_file_t));
	if(named_conf == NULL) {
		return NGX_ERROR;
	}

	value = cf->args->elts;

	///absolute path
	if(value[1].data[0] == '/') {
		path.len = value[1].len + 1;
		path.data = ngx_pcalloc(cf->pool, path.len);
		if(path.data == NULL) {
			return NGX_ERROR;
		}
		last = path.data;
		last = ngx_cpymem(last, value[1].data, value[1].len);

	} else {
		path.len = cf->cycle->conf_prefix.len + value[1].len + 1;
		path.data = ngx_pcalloc(cf->pool, path.len);
		if(path.data == NULL) {
			return NGX_ERROR;
		}

		last = path.data;
		last = ngx_cpymem(last, cf->cycle->conf_prefix.data, cf->cycle->conf_prefix.len);
		last = ngx_cpymem(last, value[1].data, value[1].len);
	}
	
	fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
	if (fd == NGX_INVALID_FILE) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_open_file_n " \"%s\" failed", path.data);
		return NGX_ERROR;
	}

	if(ngx_fd_info(fd, &named_conf->file.info) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, ngx_fd_info_n " \"%s\" failed", path.data);
		return NGX_ERROR;
	}

	
	named_conf->buffer = &buf;
	
	buf.start = ngx_alloc(NGX_CONF_BUFFER, cf->log);
	if(buf.start == NULL) {
		return NGX_ERROR;
	}

	buf.pos = buf.start;
	buf.last = buf.start;
	buf.end = buf.last + NGX_CONF_BUFFER;
	buf.temporary = 1;

	named_conf->file.fd = fd;
	named_conf->file.name.len = path.len;
	named_conf->file.name.data = path.data;
	named_conf->file.offset = 0;
	named_conf->file.log = cf->log;
	named_conf->line = 1;

	prev = cf->conf_file;
	cf->conf_file = named_conf;

	for( ;; ) {
		rc = ngx_http_mdns_conf_read_token(cf);
		
		if(rc == NGX_ERROR) {
			goto done;
		}

		if(rc == NGX_CONF_BLOCK_DONE) {
			continue;
		}

		if(rc == NGX_CONF_FILE_DONE) {
			goto done;
		}

		if(rc == NGX_CONF_BLOCK_START) {

			value = cf->args->elts;

			//key: view, match-clients, zone, forwarders, backupers
			if(value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"view", 4) == 0) {

				type = parse_view;

				view_index ++;

				view = ngx_array_push(views);
				if(view == NULL) {
					goto failed;
				}
				end = value[1].data + value[1].len;
				q = ngx_strlchr(value[1].data, end, ':');
				if(q == NULL) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid directive [%s]", value[1].data);
					goto failed;
				}
				view->name.data = value[1].data;
				view->name.len = q - value[1].data;
				view->server_index = 0;

				ngx_array_init(&view->servers, cf->pool, 8, sizeof(ngx_str_t));
				q ++;
				while(1) {
					start = q;
					while(*q && *q != ',' && q < end) q++;
					if(q - start > 0){
						ip = ngx_inet_addr(start, q - start);
						if(ip == INADDR_NONE) {
							ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "valid ip [%s]", value[1].data);
							goto failed;
						}
						server = ngx_array_push(&view->servers);
						if(server == NULL) {
							goto failed;
						}
						server->data = start;
						server->len = q - start;
					}
					q ++;
					if(q >= end) {
						break;
					}
				}

			} else if (value[0].len == 13 && ngx_strncasecmp(value[0].data, (u_char*)"match-clients", 13) == 0) {

				type = parse_match_client;
		
			} else {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown directive [%s]", value[0].data);
				goto failed;
			}
			continue;
		}

		//rc = NGX_OK;
		if(type == parse_view) {

		}else if(type == parse_match_client) {

			value = cf->args->elts;

			if(value[0].len == 3 && ngx_strncasecmp(value[0].data, (u_char*)"any", value[0].len) == 0) {
				*any_view = view;
			} else {
				last = value[0].data + value[0].len;
				slash = ngx_strlchr(value[0].data, last, '/');
				if(slash == NULL) {
					goto failed;
				}
				ip = ngx_inet_addr(value[0].data, slash-value[0].data);
				if(ip == INADDR_NONE) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "valid ip [%s]", value[0].data);
					goto failed;
				}
				slash ++;
				mask = 0xffffffff;
				mask_size = ngx_atoi(slash,last-slash);
				if(mask_size == NGX_ERROR || mask_size < 1|| mask_size > 32) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "valid ip mask [%s]", slash);
					goto failed;
				}
				
				rc = ngx_radix32tree_insert(tree, ntohl(ip), mask<<(32-mask_size), view_index);
				if( rc == NGX_ERROR) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "radix insert error");
					goto failed;
				}
			}
		}
	}

	
failed:

	rc = NGX_ERROR;

done:
	
	cf->conf_file = prev;

	if(named_conf->buffer->start) {
		ngx_free(named_conf->buffer->start);
	}

	if(rc == NGX_ERROR) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http_mdns_conf_read_token(ngx_conf_t *cf) 
{
	u_char      *start, ch, *src, *dst;
	off_t        file_size;
	size_t       len;
	ssize_t      n, size;
	ngx_uint_t   found, need_space, last_space, sharp_comment, variable;
	ngx_uint_t   quoted, s_quoted, d_quoted, start_line;
	ngx_str_t   *word;
	ngx_buf_t   *b;

	found = 0;
	need_space = 0;
	last_space = 1;
	sharp_comment = 0;
	variable = 0;
	quoted = 0;
	s_quoted = 0;
	d_quoted = 0;

	cf->args->nelts = 0;
	b = cf->conf_file->buffer;
	start = b->pos;
	start_line = cf->conf_file->line;

	file_size = ngx_file_size(&cf->conf_file->file.info);

	for ( ;; ) {

		if (b->pos >= b->last) {

			if (cf->conf_file->file.offset >= file_size) {

				if (cf->args->nelts > 0 || !last_space) {

					if (cf->conf_file->file.fd == NGX_INVALID_FILE) {
						ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"unexpected end of parameter, "
								"expecting \";\"");
						return NGX_ERROR;
					}

					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"unexpected end of file, "
							"expecting \";\" or \"}\"");
					return NGX_ERROR;
				}

				return NGX_CONF_FILE_DONE;
			}

			len = b->pos - start;

			if (len == NGX_CONF_BUFFER) {
				cf->conf_file->line = start_line;

				if (d_quoted) {
					ch = '"';

				} else if (s_quoted) {
					ch = '\'';

				} else {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"too long parameter \"%*s...\" started",
							10, start);
					return NGX_ERROR;
				}

				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"too long parameter, probably "
						"missing terminating \"%c\" character", ch);
				return NGX_ERROR;
			}

			if (len) {
				ngx_memmove(b->start, start, len);
			}

			size = (ssize_t) (file_size - cf->conf_file->file.offset);

			if (size > b->end - (b->start + len)) {
				size = b->end - (b->start + len);
			}

			n = ngx_read_file(&cf->conf_file->file, b->start + len, size,
					cf->conf_file->file.offset);

			if (n == NGX_ERROR) {
				return NGX_ERROR;
			}

			if (n != size) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						ngx_read_file_n " returned "
						"only %z bytes instead of %z",
						n, size);
				return NGX_ERROR;
			}

			b->pos = b->start + len;
			b->last = b->pos + n;
			start = b->start;
		}

		ch = *b->pos++;

		if (ch == LF) {
			cf->conf_file->line++;

			if (sharp_comment) {
				sharp_comment = 0;
			}
		}

		if (sharp_comment) {
			continue;
		}

		if (quoted) {
			quoted = 0;
			continue;
		}

		if (need_space) {
			if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
				last_space = 1;
				need_space = 0;
				continue;
			}

			if (ch == ';') {
				return NGX_OK;
			}

			if (ch == '{') {
				return NGX_CONF_BLOCK_START;
			}

			if (ch == ')') {
				last_space = 1;
				need_space = 0;

			} else {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"unexpected \"%c\"", ch);
				return NGX_ERROR;
			}
		}

		if (last_space) {
			if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
				continue;
			}

			start = b->pos - 1;
			start_line = cf->conf_file->line;

			switch (ch) {

				case ';':
				case '{':
					if (cf->args->nelts == 0) {
						ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"unexpected \"%c\"", ch);
						return NGX_ERROR;
					}

					if (ch == '{') {
						return NGX_CONF_BLOCK_START;
					}

					return NGX_OK;

				case '}':
					if (cf->args->nelts != 0) {
						ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"unexpected \"}\"");
						return NGX_ERROR;
					}

					return NGX_CONF_BLOCK_DONE;

				case '#':
					sharp_comment = 1;
					continue;

				case '\\':
					quoted = 1;
					last_space = 0;
					continue;

				case '"':
					start++;
					d_quoted = 1;
					last_space = 0;
					continue;

				case '\'':
					start++;
					s_quoted = 1;
					last_space = 0;
					continue;

				default:
					last_space = 0;
			}

		} else {
			if (ch == '{' && variable) {
				continue;
			}

			variable = 0;

			if (ch == '\\') {
				quoted = 1;
				continue;
			}

			if (ch == '$') {
				variable = 1;
				continue;
			}

			if (d_quoted) {
				if (ch == '"') {
					d_quoted = 0;
					need_space = 1;
					found = 1;
				}

			} else if (s_quoted) {
				if (ch == '\'') {
					s_quoted = 0;
					need_space = 1;
					found = 1;
				}

			} else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
					|| ch == ';' || ch == '{')
			{
				last_space = 1;
				found = 1;
			}

			if (found) {
				word = ngx_array_push(cf->args);
				if (word == NULL) {
					return NGX_ERROR;
				}

				word->data = ngx_pnalloc(cf->pool, b->pos - start + 1);
				if (word->data == NULL) {
					return NGX_ERROR;
				}

				for (dst = word->data, src = start, len = 0;
						src < b->pos - 1;
						len++)
				{
					if (*src == '\\') {
						switch (src[1]) {
							case '"':
							case '\'':
							case '\\':
								src++;
								break;

							case 't':
								*dst++ = '\t';
								src += 2;
								continue;

							case 'r':
								*dst++ = '\r';
								src += 2;
								continue;

							case 'n':
								*dst++ = '\n';
								src += 2;
								continue;
						}

					}
					*dst++ = *src++;
				}
				*dst = '\0';
				word->len = len;

				if (ch == ';') {
					return NGX_OK;
				}

				if (ch == '{') {
					return NGX_CONF_BLOCK_START;
				}

				found = 0;
			}
		}
	}
}

static ngx_int_t
ngx_http_mdns_get_ifreq(ngx_conf_t *cf, ngx_http_mdns_loc_conf_t *conf)
{
	ngx_socket_t	fd;
	ngx_uint_t		num;
	struct ifreq	buf[16];
	struct ifconf	ifc;
	ngx_str_t		p, *p_array;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1) {
		return NGX_ERROR;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t)buf;

	if(ioctl(fd, SIOCGIFCONF, &ifc) < 0){
		return NGX_ERROR;
	}

	num = ifc.ifc_len / sizeof(struct ifreq);
		
	while(num--) {
		if(ioctl(fd, SIOCGIFADDR, (char *)&buf[num])) {
			close(fd);
			return NGX_ERROR;
		}

		p.len = ngx_strlen(inet_ntoa(((struct sockaddr_in *) &buf[num].ifr_addr)->sin_addr)) + 1;
		p.data = ngx_pcalloc(cf->pool, p.len);
		if(p.data == NULL) {
			close(fd);
			return NGX_ERROR;
		}
		memcpy(p.data, inet_ntoa(((struct sockaddr_in *) &buf[num].ifr_addr)->sin_addr), p.len);

		if((ntohl(inet_addr((const char*)p.data)) >= ntohl(inet_addr("10.0.0.0"))  && 
						ntohl(inet_addr((const char*)p.data)) <= ntohl(inet_addr("10.255.255.255"))) ||
			(ntohl(inet_addr((const char*)p.data)) >= ntohl(inet_addr("172.16.0.0"))  &&
						ntohl(inet_addr((const char*)p.data)) <= ntohl(inet_addr("172.31.255.255"))) ||
			(ntohl(inet_addr((const char*)p.data)) >= ntohl(inet_addr("192.168.0.0"))  &&
						ntohl(inet_addr((const char*)p.data)) <= ntohl(inet_addr("192.168.255.255"))))
		{
			continue;
		}

		if(ntohl(inet_addr((const char*)p.data)) == ntohl(inet_addr("127.0.0.1"))) {
			continue;
		}

		p_array = ngx_array_push(conf->mac_ip);
		if(p_array == NULL) {
			close(fd);
			return NGX_ERROR;
		}

		p_array->len = p.len - 1;
		p_array->data = p.data;
	}

	close(fd);
	return NGX_OK;
}

static ngx_int_t ngx_http_mdns_pre(ngx_conf_t *cf)
{
	ngx_http_mdns_loc_conf_t *mdcf;

	mdcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_mdns_module);

	mdcf->mac_ip = ngx_array_create(cf->pool, 10, sizeof(ngx_str_t));
	if(mdcf->mac_ip == NULL){
		return NGX_ERROR;
	}

	if(ngx_http_mdns_get_ifreq(cf, mdcf) != NGX_OK) {
		return NGX_ERROR;
	}

	return NGX_OK;
}
