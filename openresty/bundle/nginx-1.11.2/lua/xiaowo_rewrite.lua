local _M ={ }

local function unescape(w)  
    s=string.gsub(w,"+"," ")  
    s,n = string.gsub(s,"%%(%x%x)",function(c)  
        return string.char(tonumber(c,16))  
    end)  
    return s  
end  

function _M.rewrite_uri()
	 local new_uri = string.gsub(ngx.var.uri, "(__)(%x)(%x)", "%%%2%3")
	 ngx.req.set_uri(unescape(new_uri))
end

return _M

