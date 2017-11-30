local _M =
{
}
function _M.anti_stealing_link()

    local requrl = ngx.var.scheme.."://"..ngx.var.host
    if ngx.var.uri then
        requrl = requrl .. ngx.var.uri
    end
    if ngx.var.is_args then
        requrl = requrl .. ngx.var.is_args
    end
    if ngx.var.query_string then
        requrl = requrl .. ngx.var.query_string
    end

	local conf = require "chinamobile_auth_conf"
	if not conf then
	    ngx.log(ngx.ERR, "chinamobile_auth_conf.lua is not exist!")
	    return
	end 
	if #conf == 0 then
	    return
	end

	local match = {}
	for i=1,#conf do
		if not conf[i].url or not conf[i].s or not conf[i].e then
			ngx.log(ngx.ERR, "error: ", err)
	        return
		end
		local m, err = ngx.re.match(requrl, conf[i].url)
		if m then
			table.insert(match, i)
		else
			if err then
				ngx.log(ngx.ERR, "error: ", err)
	            return
			end
		end
	end

	function gettimeHM( stime )
		local hour,minu
		if string.len(stime) ~= 5 or string.sub(stime,3,3) ~= ":" then
			return false,0,0
		end
		hour = tonumber(string.sub(stime,1,2))
		if not hour then
			return false,0,0
		end
		minu = tonumber(string.sub(stime,4,5))
		if not minu then
			return false,0,0
		end
		if hour > 23 or minu > 59 then
			return false,0,0
		else
			return true,hour,minu
		end
	end

	for i=1, #match do
		local checkconf = true	
		local confidx = match[i]
		local r,sh,sm = gettimeHM(conf[confidx].s)
		if r == false then
			checkconf = false
		end
		local r,eh,em = gettimeHM(conf[confidx].e)
		if r == false then
			checkconf = false
		end

		local startime = sh * 60 + sm
		local endtime = eh * 60 + em
		if startime > endtime then
			checkconf = false
		end

		if checkconf == true then
			local curtime = os.date("%H")*60 + os.date("%M")
			if startime <= curtime and endtime >= curtime then
				ngx.header["Content-Length"] = 0
				ngx.exit(ngx.HTTP_OK)
			end
		end
	end
	
end
return _M

