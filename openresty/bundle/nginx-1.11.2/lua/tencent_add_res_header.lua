local cfg = require "tencent_add_res_header_cfg"
local _M={}
function _M.add_header()
	if not cfg then
		ngx.log(ngx.ERR, "tencent_add_res_header plugin error config file!")
		return
	end

	if #cfg == 0 then
		return
	end

	local value = ngx.req.get_headers()["origin"]

	if not value then
		return
	end

	local mt = false
	local ret = nil
	for i=1, #cfg do
		ret = ngx.re.match(value, cfg[i])
		if ret and ret[1] and ret[2] and ret[3] then
			mt = true
			break
		end
	end

	if not mt then
		return
	end

	local st = ret[1] .. "." .. ret[2] .. "." .. ret[3]
	ngx.header["Access-Control-Allow-Origin"] = st

	return
end
return _M
