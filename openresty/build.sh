#!/bin/bash

ngxpath=bundle/nginx-1.11.2

echo -e "configure...\n"
./configure --prefix=/usr/local/openresty  --with-http_v2_module --without-select_module --without-poll_module --without-http_upstream_ip_hash_module --with-http_stub_status_module --with-http_perl_module --with-http_flv_module --add-module=$ngxpath/src/mod_handler/check_and_chash_module --add-module=$ngxpath/src/mod_handler/limit_req_number --add-module=$ngxpath/src/mod_handler/web_rate --add-module=$ngxpath/src/mod_handler/nginx_url2gbk_src/mod_handler/url_gbk --add-module=bundle/ngx-http-split-log-module --add-module=./bundle/dnion-nginx-module-1.0/ --with-http_slice_module --with-ld-opt="-Wl,-E"

echo -e "begin make...\n"
make
echo -e "end make...\n"

echo -e "make install..\n"
make install
