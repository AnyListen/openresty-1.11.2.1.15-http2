local os = require "os"

local _M =
{
}

function _M.anti_stealing_link()
    local uri = ngx.var.uri
    local args = ngx.req.get_uri_args()

    local arglist = {"ts", "tk", "v"}
    for i ,val in pairs(arglist) do
        if type(args[val]) == "table" then
            ngx.exit(ngx.HTTP_FORBIDDEN)
        elseif type(args[val]) == "nil" then
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    local ts = args["ts"]
    local tk = args["tk"]
    local v = args["v"]

    --1 verify time format, time len must equal 12
    local p,q = ngx.re.match(ts, "^[0-9]{12}$")
    if not p then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local tssec = os.time({ year = tonumber(string.sub(ts,1,4)), month = tonumber(string.sub(ts,5,6)), 
                          day =  tonumber(string.sub(ts,7,8)), hour = tonumber(string.sub(ts,9,10)), 
                          min = tonumber(string.sub(ts,11,12)), sec=0})
    local cursec= os.time()
    local secdiff = math.abs(cursec-tssec)

    --2. verify safety chain
    local conf = require "china_mobile_app_market_dasl_conf"
    if not conf then
        ngx.log(ngx.ERR, "china_mobile_app_market_dasl_conf.lua is not exist!")
        return
    end 
    if #conf == 0 then
        return
    end

    local match = 0
    for i=1,#conf do
        if tonumber(v) ==  tonumber(conf[i].v) then
            match = i
            break
        end
    end

    if match == 0 then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if secdiff >= conf[match].e then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local md5 = ngx.md5(uri..ts..conf[match].p)
    local md5cmp = string.sub(md5,1,4)

    if md5cmp ~= tk then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end
return _M

