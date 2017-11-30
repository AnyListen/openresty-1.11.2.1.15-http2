local json = require "cjson"

local _M =
{
}

function decode(body)
    return json.decode(body)
end

function string_split(str, delimiter)
    if str==nil or str=='' or delimiter==nil then
        return nil 
    end 
    local result = {}
    for match in (str..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match)
    end 
    return result
end

function _M.anti_stealing_link()
    local conf = require "baikexinxi_auth_cfg"
    if not conf then
        ngx.log(ngx.ERR, "baikexinxi_auth_cfg.lua is not exist!")
        return
    end 
    if #conf == 0 then
        return
    end

    local uri = ngx.var.uri

    local url = ngx.var.scheme.."://"..ngx.var.host
    if ngx.var.uri then
        url = url .. ngx.var.uri
    end
    if ngx.var.is_args then
        url = url .. ngx.var.is_args
    end
    if ngx.var.query_string then
        url = url .. ngx.var.query_string
    end

    local url_args = ngx.var.args

    -- check url_regex and auth_channel_regex in config file
    for i=1,#conf do
        if not conf[i].url_regex or not conf[i].auth_channel_regex or not conf[i].auth_path then
           return 
        end

        local m, err = ngx.re.match(url, conf[i].url_regex)
        if m then
            -- url matched, do auth.

            -- if request args with 'wsSession=', skip auth
            local skip = "wsSession="
            if url_args then
                local _, q = string.find(url_args, skip)
                if q then
                    return
                end
            end

            m, err = ngx.re.match(url, conf[i].auth_channel_regex)
            if m then
                local charg = "&channel=" .. m[1]
                local res = ngx.location.capture(conf[i].auth_path,
                    {args = ngx.var.args..charg,copy_all_vars = true});

                local ret,code = pcall(decode, res.body)
                if not ret or code ~= 1 then
                    ngx.exit(ngx.HTTP_FORBIDDEN)
                end
                return
            else
                if err then
                    ngx.log(ngx.ERR, "error: ", err)
                    return
                end
            end
        else
            if err then
                ngx.log(ngx.ERR, "error: ", err)
                return
            end
        end
    end
end
return _M



