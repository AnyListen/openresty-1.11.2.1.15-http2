local ffi = require "ffi"
local key = ffi.new("char[10]","pcscdn")
ffi.cdef[[
	void decrypt(char *xcode, char *key,char *out_buf);
	void encrypt(char *str, char *key,char *out_buf);
	]]
local _M =
{
}
local function dd(...)
	ngx.log(ngx.ERR, ...)
end

string.split = function(s, p)
    local rt= {}
    string.gsub(s, '[^'..p..']+', function(w) table.insert(rt, w) end )
    return rt
end

function string.split1(str, delimiter)
	if str==nil or str=='' or delimiter==nil then
		return nil
	end
	
    local result = {}
    for match in (str..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match)
    end
    return result
end

function _M.anti_stealing_link()
	if ngx.is_subrequest then
	   return ngx.HTTP_OK
	end 

	local blowfish = ffi.load(ngx.var.blowfishpath)

	--host:pcs.yd.jomodns.com,pcs.yd.isurecdn.com  rewrite
	ngx.var.newhost =  ngx.req.get_headers()["Host"]
	if ngx.var.http_host == "pcs.yd.jomodns.com" or ngx.var.http_host == "pcs.yd.isurecdn.com" then
	   local i, j = string.find(ngx.var.uri, "/",2)
	   if j then
		  ngx.var.newhost = string.sub(ngx.var.uri,2,j - 1)
		  ngx.req.set_uri(string.sub(ngx.var.uri, j),false)
	   end
	end
		  
	--if-range etag 校验
	local ifrange = ngx.req.get_headers()["If-range"]
	if ifrange and ifrange ~= "" then
	  local ifetag, err = ngx.re.match(ifrange,'"$')
	   if ifetag == nil then
		 local time = ngx.parse_http_time(ifrange)
		 if time == nil then
			 ngx.req.set_header("If-range",'"'..ifrange..'"')
		 end
	   end
	end
	--Referer访问限制
	--uri_referer = "http://"..ngx.var.host..ngx.var.uri
	if ngx.var.http_referer and ngx.var.http_referer ~= "" then
	   local m, err = ngx.re.match(ngx.var.http_referer,'\\.(baidu|baidupcs)\\.com')
	   if m == nil then
		  return ngx.redirect("http://www.baidupcs.com/403.html",302)
	   end
	end

	local m, err = ngx.re.match(ngx.var.uri,"(domain|crossdomain)\\.xml")
	if m ~= nil then
	   return ngx.HTTP_OK
	end

	--xcod
	local p_xcode = ngx.var.arg_xcode
	if p_xcode == nil then
	   return ngx.redirect("http://www.baidupcs.com/401.html",302)
	end

	local xcode = ffi.new("char[2000]",p_xcode)
    local dcode = ffi.new("char[1000]");
	--local xsddtr = ffi.new("char[1000]");
	--local str = ffi.new("char[2000]","1576257884,100,1220706174");


	blowfish.decrypt(xcode, key, dcode)
	--blowfish.encrypt(str,key,xstr)
	local decode = ffi.string(dcode)
	local list = string.split1(decode, ",");
	if list == nil or table.getn(list) < 3 then
	  return ngx.redirect("http://www.baidupcs.com/401.html",302)
	end

	--超时判断
	local timeover = tonumber(list[1])
	if timeover == nil or timeover < ngx.time() then
	  return ngx.redirect("http://www.baidupcs.com/401.html",302)
	end
	--限速
	if list[2] ~= "" and tonumber(list[2]) == nil then
	  return ngx.redirect("http://www.baidupcs.com/401.html",302)
	end
	if list[2] ~= "" and tonumber(list[2]) > 0 then
	   ngx.var.limit_rate = list[2].."K"
	end

	local crc32 = string.gsub(ngx.var.uri," ","%%20")
	--crc32
	if list[3] ~= "" and tostring(ngx.crc32_long(crc32)) ~= list[3] then
	  return ngx.redirect("http://www.baidupcs.com/401.html",302)
	end

	--鉴权
	if table.getn(list) == 4 and list[4] == "1" then
	   local response = ngx.location.capture('/authentication'..ngx.var.uri,{ args = ngx.encode_args(ngx.req.get_uri_args()) })
	   if response.status == ngx.HTTP_FORBIDDEN and response.header["x-bs-request-id"] ~= nil then 
		  return ngx.redirect("http://www.baidupcs.com/403.html",302)
	   end 
	end
end

function _M.modify_header()
	--header头设置 Content-Disposition: attachment;filename=”xxx”
	local args = ngx.req.get_uri_args()
	local fn = args[ngx.var.fnkey]
	if fn ~= nil then
	   ngx.header["Content-Disposition"] = "attachment;filename=\""..fn.."\""
	end

	--跨域资源共享 CORS策略
	local origin = ngx.req.get_headers()["Origin"]
	local referer = ngx.req.get_headers()["Referer"]
	if origin ~= nil then
	   local m, err = ngx.re.match(origin,"\\.baidu\\.com$")
	   if m ~= nil then
		  ngx.header["Access-Control-Allow-Credentials"] = "true"
		  ngx.header["Access-Control-Allow-Origin"] = origin
		  ngx.header["Access-Control-Allow-Headers"] = "Range, Origin, Content-Type, Accept, Content-Length"
		  ngx.header["Access-Control-Allow-Methods"] = "HEAD, GET, OPTIONS, PUT, POST, DELETE"
		  ngx.header["Access-Control-Expose-Headers"] = "Content-Length, ETag, x-bs-request-id, x-pcs-request-id"
	   else
		 if origin == "null" and referer ~= nil then
				local r, err = ngx.re.match(referer,"\\.baidu\\.com$")
			if r ~= nil then
			ngx.header["Access-Control-Allow-Credentials"] = "true"
			ngx.header["Access-Control-Allow-Origin"] = "null"
			ngx.header["Access-Control-Allow-Headers"] = "Range, Origin, Content-Type, Accept, Content-Length"
			ngx.header["Access-Control-Allow-Methods"] = "HEAD, GET, OPTIONS, PUT, POST, DELETE"
			ngx.header["Access-Control-Expose-Headers"] = "Content-Length, ETag, x-bs-request-id, x-pcs-request-id"
			end 
		 end
	   
	   end
	end
end
return _M
