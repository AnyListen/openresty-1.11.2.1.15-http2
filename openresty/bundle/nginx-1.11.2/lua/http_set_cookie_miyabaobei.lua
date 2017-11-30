local conf = require "miyabaobei_conf"
local ck = require "resty.cookie"

local re_match = ngx.re.match

local ngx_var = ngx.var
local ngx_req = ngx.req
local ngx_md5 = ngx.md5
local ngx_time = ngx.time
local ngx_cookie_time = ngx.cookie_time
local ngx_req_get_uri_args = ngx_req.get_uri_args

local str_sub = string.sub

local random = math.random


local re_option = "io"

local aflag = "from"
local cflag = "sitefrom"

local _M = {
	
}

local function set_cookie_helper()
	local args = ngx_req_get_uri_args()

	local arg_from = args[aflag]
	if arg_from ~= nil then
		local cookie, err = ck:new()
		if not cookie then
			return
		end

		local sitefrom, err = cookie:get(cflag)

		if sitefrom and sitefrom == arg_from then
			return
		end

		local expire = ngx_time() 
		if str_sub(arg_from, 1, 2) == "2c" then
			expire = expire + 14 * 86400
		else
			expire = expire + 86400
		end

		cookie:set({
			key = "sitefrom",
			value = arg_from,
			path = "/",
			domain = ".miyabaobei.com",
			expires = ngx_cookie_time(expire)
		})

		local sid = ngx_md5((random() + ngx_time()) .. ngx_var.remote_addr)

		cookie:set({
			key = "sid",
			value = sid,
			path = "/",
			domain = ".miyabaobei.com",
			expires = ngx_cookie_time(ngx_time() + 365 * 86400)
		})
	end
end


function _M.set_cookie()
	for i, host in ipairs(conf.hosts) do
		local m, err = re_match(ngx_var.host, host, re_option)
		if m then
			return set_cookie_helper() 
		end
	end
end

return _M
