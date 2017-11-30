local info = {}
info = { 
{host="www.cxdtest.com",host_caseless=1,url_regex=[[.*\.txt\?]],url_regex_caseless=1,auth_host="you.test.com",auth_port=80,auth_path="/play.do",},
{host=".*",host_caseless=1,url_regex=[[.*\.txt$]],url_regex_caseless=1,auth_host="you.test.com",auth_port=80,auth_path="/play.do",},
}
return info
