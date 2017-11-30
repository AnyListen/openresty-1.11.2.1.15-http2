local ok, info = pcall(require, "general_auth_proxy_conf")
local _M =
{
}

function match_host(conf)
  if conf.host == nil then
    return 0
  end
  if conf.host_caseless == nil then
    conf.host_caseless = 1
  end
  if conf.host == ".*" then
      return 1
  else
     if conf.host_caseless == 0 then
       if conf.host == ngx.var.http_host then
          return 1
       end
     elseif conf.host_caseless == 1 then
       local temp_host =string.lower(ngx.var.http_host)
       local conf_host =string.lower(conf.host)
       if temp_host == conf_host then
          return 1
       end
     else
     end
  end
   return 0
end

function search_regex(buf,pattern,caseless)
  if pattern ==".*" or pattern =="(.*)" then
     return 1
  else
     if caseless == 0 then
        local from, to, err = ngx.re.find(buf,conf[i].pattern)
        if from then
          return 1
        end
     elseif caseless == 1 then
        local from, to, err = ngx.re.find(buf,pattern,"i")
           if from then
              return 1
           end
     else
     end
  end
  return 0
end
function get_host_conf(conf)
  local tab = {}
  for i=1,#conf do
    local host_match = match_host(conf[i])
    if host_match == 1 then
       table.insert(tab,conf[i])
    end
  end
  return tab
end

function get_url_conf(conf)
  local tab = {}
  for i=1,#conf do
    local url_match=search_regex(ngx.var.uri,conf[i].url_regex,conf[i].url_regex_caseless)
    if url_match ==1 then
       table.insert(tab,conf[i])
    end
  end
  return tab
end


function find_valid_conf(conf)
  ngx.log(ngx.DEBUG,"begin to find valid conf","size of conf is ",table.getn(conf))
  for i=1,#conf do
    if conf[i].auth_host and conf[i].auth_port and conf[i].auth_path then
       return conf[i]
    end
  end
  return nil
end

function _M.auth()
	if not ok or type(info) ~= "table" then
	  ngx.log(ngx.ERR,"not find config: general_auth_proxy_conf.lua"," or config format err(",info,")")
	  return
	end
	
	--PURGE方法忽略
	if ngx.var.request_method =="PURGE" then
	  return
	end
	--查找是否有存在匹配host
	local host_conf = get_host_conf(info)
	if host_conf == nil or table.getn(host_conf) == 0 then
	  ngx.log(ngx.INFO,"available host conf is not found","!")
	  return
	end
	local url_conf = get_url_conf(host_conf)
	if url_conf == nil or table.getn(url_conf) == 0 then
	  ngx.log(ngx.INFO,"available url conf is not found","!")
	  return
	end
	local fin_conf = find_valid_conf(url_conf)
	if fin_conf == nil then
	  ngx.log(ngx.DEBUG,"available conf is not found for",ngx.var.request_uri)
	  return ngx.exit(403)
	end
	--[[即使是通用鉴权也需要在nginx 对应的server 中建立鉴权的location
	       location /auth_path {
	            proxy_pass http://auth_host:port;
	            proxy_set_header   Host auth_host;
	        }
	--]]
	
	local res = ngx.location.capture(fin_conf.auth_path,
	                {args = ngx.var.args,method = ngx.HTTP_GET,copy_all_vars = true})
	if res.status ~= ngx.HTTP_OK then
	    ngx.log(ngx.DEBUG,"subrequest return",res.status)
	    ngx.exit(ngx.HTTP_FORBIDDEN)
	else
	   local result = tostring(res.body)
	   result =ngx.re.gsub(result,"[\\s\\n]","")
	   if result == "1" then
	      ngx.log(ngx.DEBUG,"auth success,return body:",result,"--size:",string.len(result))
	     return
	   else
	     ngx.log(ngx.DEBUG,"auth failed,return body:",result,"--size:",string.len(result))
	     ngx.exit(ngx.HTTP_FORBIDDEN)
	   end
	end
end
return _M