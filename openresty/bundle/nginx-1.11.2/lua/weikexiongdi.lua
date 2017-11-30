local cfg = require "weikexiongdi_cfg"
local _M = {}
function _M.anti_stealing_link()
	if not cfg then
		ngx.log(ngx.ERR, "the weikexiongdi's lua config file not exist!")
		return
	end

	if #cfg == 0 then
		return
	end

	local idx = -1 
	local key_ver = false
	local password = nil
	local duration = nil
	for i=1, #cfg do
		local m = ngx.re.match(ngx.var.uri, cfg[i].urireg)
		if m then
			idx = i
			key_ver = cfg[i].key_ver
			password = cfg[i].password
			duration = cfg[i].duration
			break
		end
	end

	if idx < 0 then
		ngx.log(ngx.INFO, "the weikexiongdi can't find match!")
		return
	end

	local args_st = ngx.var.arg_st
	local args_e = ngx.var.arg_e
	if not args_st or not args_e or args_st == "" or args_e == "" then
	    ngx.log(ngx.INFO, "the weikexiongdi st e value is invalid!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	local time = tonumber(args_e)
	local now = ngx.now()
	if not time then
		ngx.log(ngx.INFO, "the weikexiongdi e value is not number!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	if now > time + duration then
		ngx.log(ngx.INFO, "the weikexiongdi the time expire!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end


	if key_ver then
		local args_key = ngx.var.arg_key
		if not args_key or args_key == ""  then
			ngx.log(ngx.INFO, "the weikexiongdi key's value is nil!")
			ngx.exit(ngx.HTTP_FORBIDDEN)
			return
		end

		local md5_key = ngx.md5(password .. ngx.var.remote_addr)
		ngx.log(ngx.INFO, "the weikexiongdi md5:" .. md5_key)
		md5_key = string.lower(md5_key)
		args_key = string.lower(args_key)
		if md5_key ~= args_key then
			ngx.log(ngx.INFO, "the weikexiongdi the key is not equal!")
			ngx.exit(ngx.HTTP_FORBIDDEN)
			return
		end
	end

	local result = tonumber(args_e)
	if not result then
		ngx.log(ngx.INFO, "the weikexiongdi e is not number!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	local md5_st = ngx.md5(password .. ngx.var.uri .. args_e)

	md5_st = string.lower(md5_st)
	md5_st = string.sub(md5_st, 9, 24)

	local basecode = ngx.encode_base64(md5_st)
	basecode = string.gsub(basecode, "+", "-")
	basecode = string.gsub(basecode, "/", "_")
	basecode = string.gsub(basecode, "=", "")
	ngx.log(ngx.INFO, "the weikexiongdi base64:" .. basecode)
	if basecode ~= args_st then
		ngx.log(ngx.INFO, "the weikexiongdi base64 value is not equal!")
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end
end
return _M