local cfg = require "zazhipu_cfg"
local _M = {}
function _M.anti_stealing_link()
	if not cfg then
		ngx.log(ngx.ERR, "zazhipu's config file error!!")
		return
	end

	if #cfg == 0 then
		return
	end

	for i=1, #cfg do
		local m = ngx.re.match(ngx.var.uri, cfg[i])
		if m then
			ngx.exit(ngx.HTTP_FORBIDDEN)
			return
		end
	end
end
return _M


