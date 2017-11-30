--[[
info[defaut].request_header = {
                       { header ="User-Agent",value="@abc"},
                       { header ="SRC_IP"},
                       { header ="X-Y-Z",value="@123"},
                       { header ="A-B-C",value="123@"},
                       { header ="Cdn_Sr_Ip",value="clientip"},
}
info[www.cxdtest.com].request_header = {
                       { header ="User-Agent",value="@abc"},
                       { header ="SRC_IP"},
                       { header ="X-Y-Z",value="@123"},
                       { header ="A-B-C",value="123@"},
                       { header ="Cdn_Sr_Ip",value="clientip"},
}
]]        
function get_client_ip()
  if ngx.var.http_x_forwarded_for then
    return ngx.var.http_x_forwarded_for
  end
  if ngx.var.http_client_ip then 
    return ngx.var.http_client_ip
  end
  if ngx.var.remote_addr then
    return ngx.var.remote_addr
  end
  return nil
end
local _M =
{
}
local ok,info = pcall(require,"request_header_conf")
function _M.modify_header()
	if not ok or type(info) ~= "table" then
	   ngx.log(ngx.ERR,"not find config: request_header_conf.lua"," or config format err")
	   return
	end
	local cf = info[ngx.var.http_host]
	if cf == nil then
	  ngx.log(ngx.INFO,"host is not found in conf, user default"," conf")
	  cf = info["default"]
	end
	if cf == nil then
	  ngx.log(ngx.INFO,"no default conf,","end modify header")
	  return
	end
	local conf = cf.request_header
	if conf == nil then
	  ngx.log(ngx.INFO,"no request_header config,"," please check")
	 return
	end
	for i=1,#conf do
	  local header = conf[i].header
	  if header then
	    local header_value=ngx.req.get_headers()[header]
	    if header_value then
	      if type(header_value) =="table" then
	         header_value = table.concat(header_value)
	      end
	      if conf[i].value == nil then
	        ngx.log(ngx.DEBUG,"header[",header,"] not set value in config, will delete this header")
	        ngx.req.clear_header(header);
	      else
	        local client_ip
	        local ip_s, ip_e = string.find(conf[i].value,"clientip")
	        if ip_s  then
	          client_ip = get_client_ip()
	        end
	        local at_s, at_e = string.find(conf[i].value,"@")
	        local len = string.len(conf[i].value)
	        local temp
	        if at_s == nil then
	          if client_ip then 
	            temp = string.sub(conf[i].value,1,ip_s-1) .. client_ip .. string.sub(conf[i].value,ip_e+1,len)
	          else
	            temp = conf[i].value
	          end 
	          header_value = temp
	        elseif at_s == 1 then
	          if client_ip then 
	            temp = string.sub(conf[i].value,2,ip_s-1) .. client_ip .. string.sub(conf[i].value,ip_e+1,len)
	          else
	            temp = string.sub(conf[i].value,2,len)
	          end 
	          header_value = header_value ..";" .. temp  --ats源码中响应头与请求头的增加规则不一致，是否该保持一致？
	        elseif at_e == len then
	          if client_ip then 
	            temp = string.sub(conf[i].value,1,ip_s) ..client_ip .. string.sub(conf[i].value,ip_e+1,len-1)
	          else
	            temp = string.sub(conf[i].value,1,len-1)
	          end 
	          header_value = temp .. ";" .. header_value
	        else
	          ngx.log(ngx.ERR,"@ in the error postion,"," must at first or last")
	        end
	        ngx.req.set_header(header,header_value)
	      end
	    else
	      if conf[i].value then
	        local reconfValue = string.gsub(conf[i].value,"^@?(.-)@?$","%1")
	        if reconfValue and string.find(reconfValue,'@') == nil then
	          header_value = reconfValue
	          local ip_s, ip_e = string.find(reconfValue,"clientip")
	          if ip_s  then
	            local client_ip = get_client_ip()
	            header_value = string.sub(reconfValue,1,ip_s-1) .. client_ip ..string.sub(reconfValue,ip_e+1,string.len(reconfValue))
	          end
	          ngx.req.set_header(header,header_value)
	        else
	          ngx.log(ngx.ERR,"@ in the error postion,"," must at first or last")
	        end
	      end          
	    end
	  end
	end
end
return _M
