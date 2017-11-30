--nginx和ats的配置文件不同，nginx本身就可以灵活配置不同server,不同location不同的执行逻辑, 因此host和url可以直接通过nginx本身的配置文件nginx.conf来配置.如果在lua里面再进行一次正则匹配，会影响nginx的性能


local _M = {}

_M.password = "dnion"

return _M
