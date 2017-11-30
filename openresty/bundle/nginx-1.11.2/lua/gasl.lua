local ok,info = pcall (require, "gasl_conf")
local _M =
{
}
local ciphertext
local realpath
local encryptpath
local new_encryptpath
local time_stamp
local pair_4_valid
local pair_4
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
  local list =conf.user_agent_of_white_list
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
  if conf.status ==nil then
     conf.status =403
  end
  if conf.status == 403 then
    ngx.exit(403)
  elseif conf.status == 302 and conf.location then
    ngx.redirect(conf.location)
  else
    ngx.exit(conf.status)
  end
end

function match_host(conf)
  if conf.host == nil then
    return 0
  end
  if conf.host_caseless == nil then
     conf.host_caseless =1
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
        local from, to, err = ngx.re.find(buf,pattern)
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

function get_regex(buf,pattern,caseless)
  if caseless == 0 then
    local match, err = ngx.re.match(buf,pattern)
    if match then
      ngx.log(ngx.DEBUG,"buf[",buf,"],pattern[",pattern,"],caseless[",caseless,"] math string[", match[1],"].")
      return match[1]
    end
  elseif caseless == 1 then
    local match, err = ngx.re.match(buf,pattern,"i")
    if match then
      ngx.log(ngx.DEBUG,"buf[",buf,"],pattern[",pattern,"],caseless[",caseless,"] math string[", match[1],"].")
      return match[1]
    end
  else
  end
  ngx.log(ngx.DEBUG,"get regex failed,buf[",buf,"],pattern[",pattern,"],caseless[",caseless,"].")
  return nil
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
    ciphertext =nil
    realpath =nil
    time_stamp =nil
    pair_4_valid = 0
    pair_4 =nil
    if ngx.var.http_user_agent then
      ngx.log(ngx.DEBUG,"begin to match ","user_agent")
      local user_agent_match=search_regex(ngx.var.http_user_agent,conf[i].user_agent_regex,conf[i].user_agent_regex_caseless)
      if user_agent_match ==1 then
        --获取密文
        ngx.log(ngx.DEBUG,"user_agent match,next find ","ciphertext")
        ciphertext  = get_regex(ngx.var.request_uri,conf[i].ciphertext_regex,conf[i].ciphertext_regex_caseless)
        if ciphertext then
          --获取real_path
          ngx.log(ngx.DEBUG,"ciphertext get,next find ","realpath")
          realpath=get_regex(ngx.var.request_uri,conf[i].real_path_regex,conf[i].real_path_regex_caseless)
          encryptpath=get_regex(realpath,conf[i].encrypt_path_regex,conf[i].encrypt_path_regex_caseless)
          if encryptpath then
             encryptpath = encryptpath..conf[i].encrypt_path_add
          else
             encryptpath = realpath
          end
	  new_encryptpath=get_regex(realpath,conf[i].newencrypt_path_regex,conf[i].newencrypt_path_regex_caseless)
          if new_encryptpath then
             new_encryptpath = new_encryptpath..conf[i].newencrypt_path_add
          end
          if realpath then
            --获取time_stamp
            ngx.log(ngx.DEBUG,"realpath get,next find ","time_stamp")
            if conf[i].time_stamp_format == "yyyymd" then
              local str = ngx.today()
              time_stamp = string.gsub(str,'-','')
            else
              time_stamp = get_regex(ngx.var.request_uri,conf[i].time_stamp_regex,conf[i].time_stamp_regex_caseless)
            end
            if time_stamp then
              ngx.log(ngx.DEBUG,"time_stamp get,next find ","pair_4_valid")
              if conf[i].pair_4_regex_valid == 1 then
                pair_4_valid = 1
                pair_4 = get_regex(ngx.var.request_uri,conf[i].pair_4_regex,conf[i].pair_4_regex_caseless)
                if pair_4 then
                  return conf[i]
                else
                end  
              else
                return conf[i]
              end
            end 
          end
        end
      end
    else 
      ngx.log(ngx.DEBUG,"no ","user_agent")
    end
  end
  return nil
end

function time_format_check (time_stamp_format)
  local m,err
  if time_stamp_format == "dec" or time_stamp_format == "dec_ms" then
    m,err =ngx.re.match(time_stamp,"^\\d+$")
  elseif time_stamp_format == "hex" then
     m,err =ngx.re.match(time_stamp,"^[A-Fa-f\\d]+$")
  elseif time_stamp_format == "string" then
    m,err =ngx.re.match(time_stamp,"^\\d{14}$")
  else
  end
  return m 
end

function time_transform(timestring,format) 
  if format == "hex" then
    timestring = "0x" .. timestring 
    return tonumber(timestring)
  elseif format == "dec" or format == "dec_ms" then
    return tonumber(timestring)
  elseif  format == "string" then
    local Y = string.sub(timestring , 1, 4)  
    local M = string.sub(timestring , 5, 6)  
    local D = string.sub(timestring , 7, 8)
    local H = string.sub(timestring , 9, 10)
    local Min = string.sub(timestring , 11, 12)
    local S = string.sub(timestring , 13, 14) 
    return os.time({year=Y, month=M, day=D, hour=H,min=Min,sec=S})  
  elseif format == "yyyymd" then
    return 0
  elseif format == "yyyymmddhhmm" then
    local Y = string.sub(timestring , 1, 4)  
    local M = string.sub(timestring , 5, 6)  
    local D = string.sub(timestring , 7, 8)
    local H = string.sub(timestring , 9, 10)
    local Min = string.sub(timestring , 11, 12)
    return os.time({year=Y, month=M, day=D, hour=H,min=Min,sec=0})    
  else
      return -1
  end
end

function now_transform(format) 
  if format == "hex" then
    return string.format("%#x", math.ceil(ngx.now()))
  elseif format == "dec" or format == "dec_ms" then
    return math.ceil(ngx.now())
  elseif  format == "string" then
    return os.date("%Y%m%d%H%M%S")
  elseif format == "yyyymmddhhmm" then
    return os.date("%Y%m%d%H%M")
  else
      return nil
  end
end

function check_time_expired(time,conf)
  local now = tonumber(ngx.now())
  local format = conf.time_stamp_format
  local type
  if conf.verify_expired_time_type then
     type = tonumber(conf.verify_expired_time_type)
  end
  if type == nil then
     type = 1
  end
  local expired_time
  if conf.expired_time then
     expired_time = tonumber(conf.expired_time)
  end
  local future_boundary_of_expired_time 
  if conf.future_boundary_of_expired_time then
     future_boundary_of_expired_time = tonumber(conf.future_boundary_of_expired_time)
  end
  local past_boundary_of_expired_time
  if conf.past_boundary_of_expired_time then
     past_boundary_of_expired_time = tonumber(conf.past_boundary_of_expired_time)
  end
  if type ==1 and expired_time == nil then
    ngx.log(ngx.ERR,"conf.expired_time is nil or format err"," please check")
    return -1
  end
  if type == 3 then
    if future_boundary_of_expired_time == nil or past_boundary_of_expired_time == nil then
      ngx.log(ngx.ERR,"future_boundary_of_expired_time or past_boundary_of_expired_time err"," please check")
      return -1
    end
  end
  ngx.log(ngx.DEBUG,"time:",time,",format:",format,",type:",type)
  if format == "hex" or format == "dec" or format == "string" or format == "yyyymmddhhmm" then
    if type == 1 then
      if math.abs(now-time) <= expired_time then
        return 0
      else
        return -1
      end
    elseif type == 2 then
      if now < time then
        return 0
      else
        return -2
      end
    elseif type == 3 then
       if now-time > future_boundary_of_expired_time or time-now > past_boundary_of_expired_time then
         return -3
       else 
         return 0
       end
    else 
      return -4
    end
  elseif format == "dec_ms" then
    if type == 1 then
      if math.abs((now*1000 - time)/1000) < expired_time then
        return 0
      else 
        return -5
      end
    elseif type == 2 then
      if now < time then
        return 0
      else
        return -6
      end
    elseif type == 3 then  
      if (now*1000-time)/1000 > future_boundary_of_expired_time or (time-now*1000)/1000 > past_boundary_of_expired_time then
         return -7
       else 
         return 0
       end
    else 
      return -8
    end
  elseif time_stamp_format =="yyyymd"  then
    return 0
  else
    return -9
  end
end

function string_split(str, delimiter)
  if str==nil or str=='' or delimiter==nil then
    return nil
  end
  local result = {}
  for match in (str..delimiter):gmatch("(.-)"..delimiter) do
    table.insert(result, match)
  end
  return result
end

function get_concat(fin_conf,encrypt_field_concatenate)
  local concat = {}
	local concat_buf
	concat =string_split(encrypt_field_concatenate,',')
	ngx.log(ngx.DEBUG,"encrypt_field_concatenate:",encrypt_field_concatenate," size:",table.getn(concat))
	for i=1,#concat do
	   if concat[i] == "password" then
	     ngx.log(ngx.DEBUG,"attach ","password")
	     concat_buf = concat_buf and (concat_buf .. fin_conf.password) or fin_conf.password
	   elseif  concat[i] == "time_stamp" then
	     ngx.log(ngx.DEBUG,"attach ","time_stamp")
	     if fin_conf.encrypt_field_concatenate_time_stamp_format == "dec" then
	        if fin_conf.time_stamp_format == "dec_ms" then
	          local temp_time_stamp = fin_time/1000
	          concat_buf = concat_buf and (concat_buf .. temp_time_stamp) or temp_time_stamp
	        else
	          concat_buf = concat_buf and (concat_buf .. fin_time) or fin_time        
	        end
	     else
	       concat_buf = concat_buf and (concat_buf .. time_stamp) or time_stamp
	     end
	   elseif concat[i] == "real_path"  then
	     ngx.log(ngx.DEBUG,"attach ","real_path")
	     concat_buf = concat_buf and (concat_buf .. realpath) or realpath
	   elseif concat[i] == "encrypt_path"  then
	     ngx.log(ngx.DEBUG,"attach ","encrypt_path")
	     concat_buf = concat_buf and (concat_buf .. encryptpath) or encryptpath
	   elseif concat[i] == "new_encryptpath"  then
	     ngx.log(ngx.DEBUG,"attach ","new_encryptpath")
	     concat_buf = concat_buf and (concat_buf .. new_encryptpath) or new_encryptpath
	   elseif concat[i] == "/" then
	     ngx.log(ngx.DEBUG,"attach ","/")
	     concat_buf = concat_buf and (concat_buf .. "/") or "/"
	   elseif pair_4_valid == 1 and concat[i] == "pair_4" then
	     ngx.log(ngx.DEBUG,"attach ","pair_4")
	     concat_buf = concat_buf and (concat_buf .. pair_4) or pair_4
	   elseif concat[i] == "|" then
	     ngx.log(ngx.DEBUG,"attach ","|")
	     concat_buf = concat_buf and (concat_buf .. "|") or "|"
	   elseif concat[i] == "&" then
	     ngx.log(ngx.DEBUG,"attach ","&")
	     concat_buf = concat_buf and (concat_buf .. "&") or "&"
	   elseif concat[i] == "host" then
	     ngx.log(ngx.DEBUG,"attach ","host")
	     concat_buf = concat_buf and (concat_buf .. ngx.var.host) or ngx.var.host
	   else
	   end
	end
  return concat_buf
end
-----------
function _M.anti_stealing_link()
	if not ok or type(info) ~= "table" then
	  ngx.log(ngx.ERR,"not find config: gasl_conf.lua"," or conf format error(",info,")")
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
	--查找是否有存在匹配host
	local host_conf = get_host_conf(info.keylist)
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
	  ngx.log(ngx.INFO,"available conf is not found for",ngx.var.request_uri)
	  return ngx.exit(403)
	end
	----时间格式检查
	local time_check = time_format_check(fin_conf.time_stamp_format)
	if time_check == nil then
	  ngx.log(ngx.INFO,"time_format_check,format[",fin_conf.time_stamp_format,"].")
	  return go_exit(fin_conf)
	end
	----获取转化后的时间
	local fin_time = time_transform(time_stamp,fin_conf.time_stamp_format)
	if fin_time < 0 then
	   return go_exit(fin_conf)
	end
	ngx.log(ngx.DEBUG,"fin_time:",fin_time)
	----检查时间是否过期
	local expired_check = check_time_expired(fin_time,fin_conf)
	if expired_check < 0 then
	   ngx.log(ngx.DEBUG,"time ","expired,expired_check return ",expired_check)
	   return go_exit(fin_conf)
	end
	ngx.log(ngx.DEBUG,"time ","time_expired_check ","passed")
	local concat_buf = get_concat(fin_conf,fin_conf.encrypt_field_concatenate)
	
	local md5 = ngx.md5(concat_buf)
	ngx.log(ngx.INFO, "concat_buf:",concat_buf,"--md5:",md5)
	if string.lower(md5) == string.lower(ciphertext) then
	   ngx.req.set_uri("/"..realpath,false)
	   return
	else
	   ngx.log(ngx.INFO, "ciphertext(",ciphertext,") is invalid")
	   return go_exit(fin_conf)
	end
end
return _M
