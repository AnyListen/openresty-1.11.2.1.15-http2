local cfg = require "xiaowocfg"
local cjson = require "cjson"
local http = require "resty.http"
local aes = require "resty.aes"
local hexlib =  require "resty.string"
local os = require "os"
local _M ={ }

local function auth_by_origin(appid, app_id, mobile, package_id)
    local account = cfg["auth_account"]
    local seckey = cfg["auth_sec_key"]
    if not account or not appid or not seckey then
        return false
    end

    local now = ngx.now() * 1000
    now = tostring(now)
    local tab1 = {"DNION", "account", account, "app_id", app_id, "appid", appid, "mobile", mobile, "package_id", package_id, "timestamp", now}
    local str = table.concat(tab1)
    ngx.log(ngx.INFO, "the string used to sha512 is:" .. str)
    local sha = ngx.sha512(str)
    local md5str = sha .. seckey
    ngx.log(ngx.INFO, "auth md5str:" ..md5str)
    local md5 = ngx.md5(md5str)
    md5 = string.upper(md5)
    
    local tab2 = {"account=", account, "&app_id=", app_id, "&appid=", appid, "&mobile=", mobile, "&package_id=", package_id, "&timestamp=", now, "&sign=", md5}
    local query_str = table.concat(tab2)
    ngx.log(ngx.INFO, "the query args is:" .. query_str)

    local httpc = http.new()
    httpc:set_timeout(1000)
    httpc:connect("www.ifpflow.cn", 80)
    local res, err = httpc:request{
        path = "/xw/service/getUserFlowBalance",
        --path ="/",
        query = query_str,
    }

    if not res then
        ngx.log(ngx.ERR, "failed request to auth origin server:", err)
        return false
    end

    if res.status ~= 200 then
        ngx.log(ngx.INFO, "auth origin server return not 200 CODE!")
        return false
    end
    local reader = res.body_reader
    local body = reader(8192)
    local json = cjson.decode(body)
    if json["code"] == "215" then
	ngx.log(ngx.INFO, "auth code", json["code"])
        return true
    else
        ngx.log(ngx.INFO, "the message:", json["msg"])
        ngx.log(ngx.INFO, "the code:", json["code"])
        return false
    end
end


function _M.anti_stealing_link()
    if not cfg then
    	ngx.log(ngx.ERR, "the config file of xiaowo is nil")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    	return
    end

    local expire = cfg["expire"]
    if not expire then
        expire = 0
    end

    local ua_value = ngx.var.http_user_agent
    if not ua_value or #ua_value < 18 then
        ngx.log(ngx.INFO, "the user-agent's value is nil or invalid!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    local aeskey = cfg["aes_key"]
    if not aeskey then
        ngx.log(ngx.ERR, "no aeskey find!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    ngx.log(ngx.INFO, "user-agent:" .. ua_value)
    local tab, err = ngx.re.match(ua_value, "Dnion\\((.*)\\)")
    if not tab then
        if err then
            ngx.log(ngx.ERR, "ngx.re.match error: ", err)
            ngx.exit(ngx.HTTP_FORBIDDEN)
            return
        end
        ngx.log(ngx.INFO, "ua_value match not found")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    if not tab[1] then
        ngx.log(ngx.INFO, "match 'result  tab[1] is nil!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    ua_value = tab[1]

    local iv_value = string.sub(ua_value, -16)
    local crypet = string.sub(ua_value, 1, -18)
    if not crypet or crypet =="" then
        ngx.log(ngx.INFO, "no value need base64 decode!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    ngx.log(ngx.INFO,"iv:" .. iv_value)
    ngx.log(ngx.INFO,"crypet" ..crypet)
    local aes_cbc = aes:new(aeskey, nil, aes.cipher(256, "cbc"), {iv = iv_value})
    local decode = ngx.decode_base64(crypet)
    local decry_ret = aes_cbc:decrypt(decode)
    if not decry_ret or #decry_ret < 34 then
        ngx.log(ngx.INFO, "can't decrypt or invalid result!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    ngx.log(ngx.INFO, "after aes_decry:" .. decry_ret)
    local sign = string.sub(decry_ret, -32)
    local json_base64 = string.sub(decry_ret, 1, -34)
    if not json_base64 or #json_base64 < 1 then
        ngx.log(ngx.INFO, "invalid json encode result!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    ngx.log(ngx.INFO, "json_base64:" .. json_base64)
    local json_en = ngx.decode_base64(json_base64)
    json_en = ngx.re.gsub(json_en, "'", "\"")
    ngx.log(ngx.INFO, "json_en:" .. json_en)
    local jsontab = cjson.decode(json_en)
    if not jsontab then
        ngx.log(ngx.INFO, "json decode error!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    local arg_time = jsontab["timestamp"]
    local arg_app_id = jsontab["app_id"]
    local arg_appid = jsontab["appid"]
    local arg_mobile = jsontab["mobile"]
    local arg_packageid = jsontab["package_id"]
    local arg_tokenid = jsontab["tokenid"]

    if not arg_time or not arg_app_id or not arg_appid or not arg_mobile or not arg_packageid then
        ngx.log(ngx.INFO, "invalid argument!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    local tokenid_flag = true
    if not arg_tokenid then
        tokenid_flag = false
        arg_tokenid = "default"
    end

    local tokenlis = cfg["id_taken"]
    local token = tokenlis[arg_tokenid]
    if not token then
        ngx.log(ngx.INFO, "can't find token to match the tokenid!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    local tm = math.floor(arg_time/1000)
    if not tm then
        ngx.log(ngx.INFO, "error: timestamp can't change into number!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    local now = ngx.time()

    if now > tm + expire then
        ngx.log(ngx.INFO, "timestamp have expire time!!")
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    local tab_arg
    if tokenid_flag then
        tab_arg = {"timestamp" .. arg_time, "app_id" .. arg_app_id, "appid" .. arg_appid, "mobile" .. arg_mobile, "package_id" .. arg_packageid, "tokenid" .. arg_tokenid,}
    else
        tab_arg = {"timestamp" .. arg_time, "app_id" .. arg_app_id, "appid" .. arg_appid, "mobile" .. arg_mobile, "package_id" .. arg_packageid,}
    end

    table.sort(tab_arg)

    local argstr = "DNION" .. table.concat(tab_arg)
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

    if not auth_by_origin(arg_appid, arg_app_id, arg_mobile, arg_packageid) then
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end 
    ngx.say("ok!")
end

return _M

