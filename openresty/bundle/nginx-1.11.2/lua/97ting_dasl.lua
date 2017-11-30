local _M =
{
}
function _M.anti_stealing_link()
	local uri = ngx.var.uri
	local args = ngx.req.get_uri_args()

	--1.args is null
	if not ngx.var.args then
		return ngx.redirect("http://97ting.dnion.com/402.html")
	end

	--2.args verify
	local sig,exp,tdc
	sig = args["sig"]
	exp = args["amp;exp"]
	if not exp then
		exp = args["exp"]
	end
	tdc = args["amp;transDeliveryCode"]
	if not tdc then
		tdc = args["transDeliveryCode"]
	end

	if not sig or not exp or not tdc or string.len(exp) ~= 8 then
		return ngx.redirect("http://97ting.dnion.com/403.html")
	end

	--3.time exp verify
	local tm = string.format("%d","0x"..exp)
	local ct = os.time()
	if tonumber(tm) <= tonumber(ct) then
		return ngx.redirect("http://97ting.dnion.com/404.html")
	end

	--4.key verify
	local passwd = "atmd88xz168woha"
	local md5 = ngx.md5(passwd..ngx.var.uri..exp)
	local urlpwd = ngx.encode_base64(md5)

	urlpwd = string.gsub(urlpwd, "+", "-")
	urlpwd = string.gsub(urlpwd, "/", "_")
	urlpwd = string.gsub(urlpwd, "=", "")
	if sig ~= urlpwd then
		return ngx.redirect("http://97ting.dnion.com/405.html")
	end


	--verify pass, rewirte url
	local uri = ngx.var.uri
	local urilspot = 0
	local urilbar = 0
	local urilen = string.len(uri)
	for i = urilen, 1, -1 do
		if string.sub(uri,i,i) == "." then
			urilspot = i
			for j = urilspot, 1, -1 do
				if string.sub(uri,j,j) == "-" then
					urilbar = j
					break
				end
			end
			if urilbar ~= 0 then
				break
			end
		end
	end
	if urilspot ~= 0 and urilbar ~= 0 then
		local reuri = string.sub(uri,1,urilbar-1)
		reuri = reuri.."."..string.sub(uri,urilbar+1,urilspot-1)
		ngx.req.set_uri_args("")
		ngx.req.set_uri(reuri, false)
	end
end
return _M
