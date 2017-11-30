
local cfg = {
     ---url-regex,要设置禁止访问的url正则  s:禁止开始时间,e:禁止结束时间,时间格式必须4位
     { url = [[http://odp\.mmarket\.com/t.do\?requestid=appupgrade*]], s = '07:30',e = '10:00',},
     { url = [[http://odp\.mmarket\.com/t\.do\?requestid=backstageresident*]], s = '07:00',e = '13:00',},
     { url = [[http://odp\.mmarket\.com/t.do\?requestid=appupgrade*]], s = '15:30',e = '17:00',},
 }

return cfg
