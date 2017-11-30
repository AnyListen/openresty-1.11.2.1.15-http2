local cfg = require "yifeiyun_white_cfg"
local _M = {}

function _M.anti_stealing_link()
	if not cfg then
	--	ngx.log(ngx.ERR, "[yifeiyun_white_cfg] plugin error config file!")
		return
	end

	local fieldlist = ngx.req.get_headers()
	local host = fieldlist["host"]
	if not host or host == "chgvcache.dnion.com" then
		return
	end

	local ua = fieldlist["User-Agent"]
	if ua == "Dnion-UA-" then
		return
	end

	if #cfg == 0 then
		return
	end
	local uri = ngx.var.uri
	local uri_args = ngx.var.args

	if not uri_args then
	--	ngx.log(ngx.ERR, "uri_args is nil!\n")
		ngx.exit(ngx.HTTP_FORBIDDEN)
	end

	--ngx.log(ngx.ERR, "uri_args:" .. uri_args .. "\n")
	local url = host .. uri .. uri_args
	local uidlist = nil
	for i=1, #cfg do
		local ret = ngx.re.match(url, cfg[i].url)
		if ret then
			uidlist = cfg[i].uid
			break
		end
	end

	if not uidlist then
	--	ngx.log(ngx.ERR, "no match in config!\n")
		return
	end

	local query = ngx.req.get_uri_args()
	local uid_value = nil
	local query_k = false
	local query_t = false
	for k, v in pairs(query) do
		local key = string.lower(k)
		if key == "uid" then
			uid_value = v
		end
		if key == "k" then
			query_k = true
		end

		if key == "t" then
			query_t = true
		end

	end

	if not uid_value or not query_k or not query_t then
	--	ngx.log(ngx.ERR," no k= or no t=\n")
		ngx.exit(ngx.HTTP_FORBIDDEN)
	end

	for i=1, #uidlist do
		if uid_value == tostring(uidlist[i]) then
			return
		end
	end

	--ngx.log(ngx.ERR, "no uid in config!\n")
	ngx.exit(ngx.HTTP_FORBIDDEN)
end
return _M