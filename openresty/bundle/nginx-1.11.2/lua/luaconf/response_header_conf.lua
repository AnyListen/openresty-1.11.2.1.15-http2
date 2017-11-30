local info = {}
info["default1"] ={}
info["default1"].response_header = {
                       { header ="User-Agent",value="@abc"},
                       { header ="SRC_IP"},
                       { header ="X-Y-Z",value="@123"},
                       { header ="A-B-C",value="123@"},
                       { header ="Cdn_Sr_Ip",value="clientip"},
}
info["www.cxdtest.com"] ={}
info["www.cxdtest.com"].response_header = {
                       { header ="AA",value1="@abc"},
                       { header ="SRC_IP"},
                       { header ="BB",value="@123"},
                       { header ="CC",value="123@"},
                       { header ="DD",value="clientip"},
}
return info
---info以域名做key,不同的域名关联不同要更改的信息头
