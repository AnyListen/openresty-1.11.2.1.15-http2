local ok,info = pcall(require, "gdtv_conf")
local _M = 
{
}
   
function check_expired_time (type,time_stamp,interval)
   local now = tonumber(ngx.now())
   time_stamp = tonumber(time_stamp)
   if type == nil then
      type = 1
   end 
   if time_stamp == nil then
     ngx.log(ngx.ERR,"time_stamp format err,"," please check")
     return -1
   end
   ngx.log(ngx.DEBUG, "now:",now,"--time_stamp:",time_stamp,"--type:",type,"--interval:",interval)
   if type == 1 then
     if interval == nil or tonumber(interval) == nil then
       ngx.log(ngx.ERR,"expired_time is nil or format err,"," please check")
       return -1
     end
     if math.abs(now+7200-time_stamp) > tonumber(interval) then
       return -1
     else 
      return 0
     end
   elseif type == 2 then
      if now > time_stamp then
         return -2
      else
         return 0
      end
   else
     return -3
   end
end
function verify_host_of_white_list(conf)
  local list = conf.host_of_white_list
  if list == nil then
    return false
  end
  for i=1,#list do
      if list[i] == ngx.var.host then
          return true
      end
  end
  return false
end
function verify_user_agent_of_white_list(conf)
  if ngx.var.http_user_agent == nil  then
    return false
  end
  local list = conf.user_agent_of_white_list
  if list == nil then
    return false
  end
  for i=1,#list do
      local len = string.len(list[i])
      local tmp =string.sub(ngx.var.http_user_agent,1,len)
      ngx.log(ngx.DEBUG,"user_agent[",ngx.var.http_user_agent,"]--conf_user_agent[",list[i],"]")
      if tmp == list[i] then
         return true
      end
  end
  return false
end
function go_exit(conf)
  if conf.status == nil then
    conf.status = 403
  end
  if conf.status == 403 then
    ngx.exit(403)
  elseif conf.status == 302 and conf.location then
    ngx.redirect(conf.location)
  else
    ngx.exit(conf.status)
  end
end
function find_conf()
  local conf = info.keylist
  if conf == nil or table.getn(conf) == 0 then
     return nil
  end

   for i=1,#conf do
     local host_match = 0
     if conf[i].host then
       if conf[i].host == ".*" then
         host_match = 1
       else
         if conf[i].host_caseless ==nil then
           conf[i].host_caseless = 1
         end
         if conf[i].host_caseless == 0 then
           if conf[i].host == ngx.var.http_host then
             host_match = 1
           end
         elseif conf[i].host_caseless == 1 then
           local temp_host =string.lower(ngx.var.http_host)
           local conf_host =string.lower(conf[i].host)
           if temp_host == conf_host then
             host_match =1
           end
         else
           host_match = 0
         end 
       end
     end
     ngx.log(ngx.DEBUG,"host_match:",host_match,"--conf-host:",conf[i].host,"--url_regex:",conf[i].url_regex)
     if host_match == 1 then
       if conf[i].url_regex then
         if conf[i].url_regex ==".*" or conf[i].url_regex =="(.*)" then
           return conf[i]
         else
           if conf[i].url_regex_caseless ==nil then
              conf[i].url_regex_caseless = 1
           end
           if conf[i].url_regex_caseless == 0 then
             local from, to, err = ngx.re.find(ngx.var.uri,conf[i].url_regex)
             if from then
               return conf[i]
             end
           elseif conf[i].url_regex_caseless == 1 then
             local from, to, err = ngx.re.find(ngx.var.uri,conf[i].url_regex,"i")
             if from then
               return conf[i]
             end
           else
           end
         end
       end
     end
   end
   return nil
end
function _M.anti_stealing_link()
	if not ok or type(info) ~= "table" then
	   ngx.log(ngx.ERR,"not find config: gdtv_conf.lua"," or config format err(",info,")")
	   return
	end
	--PURGE方法忽略
	if ngx.var.request_method =="PURGE" then
	  return
	end
	--白名单忽略
	local verify_host = verify_host_of_white_list(info)
	if verify_host then
	  return
	end 
	--USER-AGENT白名单忽略
	local verify_user_agent = verify_user_agent_of_white_list(info)
	if verify_user_agent then
	   return
	end
	--查找是否有存在匹配host及url的配置项
	local fin_conf = find_conf()
	if fin_conf == nil then
	  ngx.log(ngx.INFO,"available conf is not found","!")
	  return
	end
	local uri = ngx.var.uri
	local uri_args = ngx.var.args
	
	if not uri or not uri_args then
	        ngx.log(ngx.INFO, "no uri or no args ","err")
		return go_exit(fin_conf)
	end
	--url中获取密文及时间标识
	local des, time_stamp
	local m,err = ngx.re.match(uri_args,"^_upt=([a-zA-Z\\d]{8})([\\d]+)$") 
	if not m then
	   ngx.log(ngx.INFO, "uri_args format err ",uri_args)
	   return go_exit(fin_conf)
	end 
	des= m[1]
	time_stamp = m[2]
	
	if not des or not time_stamp then
	   ngx.log(ngx.INFO, "no des or no timestamp ",des,time_stamp)
	   return go_exit(fin_conf)
	end 
	--验证时间是否过期
	local timecheck = check_expired_time(fin_conf.verify_expired_time_type,time_stamp,fin_conf.expired_time)
	if timecheck ~= 0 then
	   ngx.log(ngx.INFO, "time expired,"," access forbidden")
	   return go_exit(fin_conf)
	end
	if fin_conf.passwd == nil then
	  ngx.log(ngx.ERR,"passwd not found in conf", " please check")
	   return go_exit(fin_conf)
	end
	local buf = fin_conf.passwd ..'&' .. time_stamp ..'&' .. uri
	local md5 = ngx.md5(buf)
	ngx.log(ngx.INFO, "buf:",buf,"--md5:",md5)
	local finalstr = string.sub(md5,13,20)
	if finalstr == des then
	   return
	else
	   ngx.log(ngx.INFO, "des is invalid:",finalstr)
	   return go_exit(fin_conf)
	end
end
return _M
