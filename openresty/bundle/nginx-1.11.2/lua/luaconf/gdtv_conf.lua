local info = {}
info.keylist = {
{host=".*",host_caseless=1,url_regex=[[\.m3u8(?:\?|$)]],url_regex_caseless=1,passwd = "gdtvlivehotlinktoken",expired_time = 1800,status = 403,location= "http://www.baidu.com/",},
{host=".*",host_caseless=1,url_regex=[[\.apk(?:\?|$)]],url_regex_caseless=1,passwd = "e8486a31ff5017d15027b56426559fb0",expired_time = 1800,status = 403,location = "http://www.baidu.com/",verify_expired_time_type = 2,},
}
info.host_of_white_list={"chgvcache.dnion.com","www.cxdtest1.com",}
info.user_agent_of_white_list={"Dnion-UA-","CXD-TEST",}
return info

