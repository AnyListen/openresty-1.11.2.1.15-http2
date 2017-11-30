local conf = require "qingdashiji_conf"

local re_option = "io"
local re_match = ngx.re.match

local re_format = "(\\d{14})([0-9a-fA-F]{32})"

local ngx_get_args = ngx.req.get_uri_args
--local ngx_req_headers = ngx.req.get_headers
local ngx_exit = ngx.exit
local ngx_var = ngx.var
local ngx_md5 = ngx.md5
local ngx_status_403 = ngx.HTTP_FORBIDDEN

local str_sub = string.sub

local ign_header = "Dnion-UA-"
local ign_header_len = string.len(ign_header)

local _M = {
	
}

local function url_verify(time, md5sum)
	local str = ngx_var.uri .. time .. ngx_var.remote_addr .. conf.password

	local sum = ngx_md5(str)
	if sum == md5sum then
		return 1
	end

	return nil
end

function _M.anti_stealing_link()
	local user_agent = ngx_var.http_user_agent
	if user_agent then
		local prefix = str_sub(user_agent, 1, ign_header_len)
		if prefix == ign_header then
			return
		end
	end

	local key = ngx_get_args()["key"]
	if not key then
		return ngx_exit(ngx_status_403)
	end

	local m, err = re_match(key, re_format, re_option)
	if not m then
		return ngx_exit(ngx_status_403)
	end

	local time, md5sum = m[1], m[2]

	local res = url_verify(time, md5sum)
	if not res then
		return ngx_exit(ngx_status_403)
	end
end

return _M
