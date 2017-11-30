local cfg = require "xiaowocfg"
local _M ={ }

function _M.anti_stealing_link()
    if not cfg then
        ngx.log(ngx.ERR, "the config file of xiaowo is nil")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    local args = ngx.var.args
    if not args then
        ngx.log(ngx.INFO, "have no require args!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    local expire = cfg["expire"]
    if not expire then
        expire = 0
    end

    local tab = {}
    local userid, reqtime, packageid, sign, appid, tokenid
    for key, val in string.gmatch(args, "(%w+)=([%w_%+=%-/]+)") do
        local str_lower = string.lower(key)
        if str_lower == "userid" then
            userid = val
            table.insert(tab, key .. val)
        elseif str_lower == "reqtime" then
            reqtime = val
            table.insert(tab, key .. val)
        elseif str_lower == "packageid" then
            packageid = val
            table.insert(tab, key .. val)
        elseif str_lower == "sign" then
            sign = val
        elseif str_lower == "appid" then
            appid = val
            table.insert(tab, key .. val)
        elseif str_lower == "tokenid" then
            tokenid = val
        end
    end

    if not userid or not reqtime or not packageid or not sign or not appid then
        ngx.log(ngx.INFO, " the requir args is not complete!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    local arg_time = tonumber(reqtime)
    if not arg_time then
        ngx.log(ngx.INFO, "invalid reqTime!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    if not tokenid then
        tokenid = "default"
    end

    local tokenlis = cfg["id_taken"]
    local token = tokenlis[tokenid]
    if not token then
        ngx.log(ngx.INFO, "can't find token to match the tokenid!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    --local tm = math.floor(arg_time/1000)
    --if not tm then
    --    ngx.log(ngx.INFO, "error: timestamp can't change into number!!")
    --    ngx.exit(ngx.HTTP_FORBIDDEN)
    --    return
    --end
    local now = ngx.time()

    if now > arg_time + expire then
        ngx.log(ngx.INFO, "timestamp have expire time!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    
    table.sort(tab)

    local argstr = "DNION" .. table.concat(tab)
    ngx.log(ngx.INFO, "string sha512:"..argstr)
    local sha512_ret = ngx.sha512(argstr)
    local md5str = sha512_ret .. token
    ngx.log(ngx.INFO,"string md5:"..md5str)
    local md5_ret = ngx.md5(md5str)
    ngx.log(ngx.INFO, "md5 computer:"..md5_ret)
    --md5_ret = string.upper(md5_ret)

    if md5_ret ~= sign then
        ngx.log(ngx.INFO, "md5 auth failed!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    --ngx.say("ok!")
end

return _M
