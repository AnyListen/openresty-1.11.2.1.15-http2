local info = {}
info["default"] ={}
info["default"].request_header = {
                       { header ="User-Agent",value="@dnion"},
                       { header ="SRC_IP"},
                       { header ="X-Y-Z",value="@123"},
                       { header ="A-B-C",value="123@"},
                       { header ="Cdn_Sr_Ip",value="clientip"},
}
info["www.cxdtest1.com"] ={}
info["www.cxdtest1.com"].request_header = {
                       { header ="AA",value="@abc"},
                       { header ="SRC_IP"},
                       { header ="BB",value="@123"},
                       { header ="CC",value="123@"},
                       { header ="DD",value="clientip"},
}
return info
---info以域名做key,不同的域名关联不同要更改的信息头

