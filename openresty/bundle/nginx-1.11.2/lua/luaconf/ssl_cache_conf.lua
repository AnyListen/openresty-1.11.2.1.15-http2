
local _M = {}

_M.session_time_out = 60 * 60  --session cache保存时间, 单位s

--redis配置主备,slave is read only
_M.redis_addr = {
    master = {
        ip     = "124.239.254.51",
        port   = 6379, 
        passwd = "Dnion123456!" 
    },

    slave  = {
        ip   = "124.239.254.52",
        port = 6379,
        passwd = "Dnion123456!" 
    }
}

return _M
