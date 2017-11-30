local cfg = require "sinacfg"

local _M = {}

local function ip_auth(client_ip, ip_addr)
	local cnt = 0
	for k in string.gmatch(ip_addr, "[0-9]+") do
		cnt = cnt + 1
	end

	if cnt > 3 then
		if client_ip ~= ip_addr then
			ngx.log(ngx.ERR,"the ip with expire time verify, full ip auth failed!!")
			return false
		end
	else
		local start = string.find(client_ip, ip_addr)
		if not start then
			ngx.log(ngx.ERR,"the ip with expire time verify, ip segment auth failed!!")
			return false
		end
	end

	return true
end

function _M.anti_stealing_link(self)

	if not cfg or #cfg == 0 then
		ngx.log(ngx.ERR,"not find config: sinacfg.lua!!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	local args = ngx.req.get_uri_args()
	if not args then
		ngx.log(ngx.ERR,"the args of request is empty!!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	local expire = ngx.var.arg_expires
	local ip = ngx.var.arg_ip
	local kid = ngx.var.arg_kid
	local ssig = ngx.var.arg_ssig
        local fn = ngx.var.arg_fn

	if not ssig or not expire or not kid then
		ngx.log(ngx.ERR,"the ssig or expires or kid  is empty!!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	local now = ngx.time()
	local tm = tonumber(expire)
	if not tm then
		ngx.log(ngx.ERR,"the expire format is wrong!!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	if now > tm then
		ngx.log(ngx.ERR,"the time is expire!!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	local uri = ngx.var.uri
	local host =  ngx.var.host
	local method = ngx.req.get_method()

	local ip_expire
	local ip_addr
	local orginstr = ""
	local client_ip = ngx.var.remote_addr

	if ip then
		local pos = string.find(ip, ",")
		if pos then
			ip_expire = string.sub(ip, 1, pos-1)
			ip_addr = string.sub(ip, pos+1)

			local num = tonumber(ip_expire)
			if not num then
				ngx.log(ngx.ERR,"the ip with expire time format is invalid!")
				ngx.exit(ngx.HTTP_FORBIDDEN)
				return
			end
			if now > num then
				if not ip_auth(client_ip, ip_addr) then
					ngx.exit(ngx.HTTP_FORBIDDEN)
					return
				end
			end
		else
			if not ip_auth(client_ip, ip) then
				ngx.exit(ngx.HTTP_FORBIDDEN)
				return
			end
		end
		orginstr = orginstr .. method .. "\n\n\n" .. expire .. "\n/" .. host .. uri .. "?ip=" .. ip
	else
		orginstr = orginstr .. method .. "\n\n\n" .. expire .. "\n/" .. host .. uri
	end

	local pw
	for i=1, #cfg do
		if cfg[i].kid == kid then
			pw = cfg[i].passwd
			break
		end
	end

	if not pw then
		ngx.log(ngx.ERR,"no passwd match kid!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	local ret = ngx.encode_base64(ngx.hmac_sha1(pw, orginstr))
	ret = string.sub(ret, 6, 15)
	if ret ~=  ssig then
		ngx.log(ngx.ERR,"ssig auth failed!", "result:" .. ret, "ssig:" .. ssig)
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end
	if fn then
		local filename = string.format("attachment;filename=\"%s\"", fn)
		ngx.log(ngx.INFO, "filename:" .. filename)
		ngx.header['Content-Disposition'] = filename
	end
        --ngx.req.set_uri_args("")
end

return _M
