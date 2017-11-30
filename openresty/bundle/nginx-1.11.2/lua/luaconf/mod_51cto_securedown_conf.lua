local info = {}
info.keylist = {
{host="v2.51cto.com",host_caseless=1,url_regex=[[\.php(?:\\?|$)]],url_regex_caseless=1,passwd = "down_51cto",status = 302,location= "http://down.51cto.com/file1/405.html"},
{host=".*",host_caseless=1,url_regex=[[.*]],url_regex_caseless=1,passwd = "down_51cto",status = 302,location = "http://down.51cto.com/file1/405.html"},
}
info.host_of_white_list={"chgvcache.dnion.com","www.cxdtest1.com",}
info.user_agent_of_white_list={"Dnion-UA-","CXD-TEST",}
return info

