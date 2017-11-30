local _M =
{
}
function guid()
   local seed={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v'}
   local tb={}
    for i=1,32 do
    table.insert(tb,seed[math.random(1,32)])
    end
    local sid =table.concat(tb)
    return sid
end
function _M.set_id_and_hop()
  if ngx.var.http_x_request_id  == nil then
     if ngx.var.request_id then
       ngx.req.set_header("X-Request-ID",ngx.var.request_id)
     else
       ngx.req.set_header("X-Request-ID",guid())
     end
  end
  if ngx.var.http_x_request_hop == nil then
     ngx.req.set_header("X-Request-HOP","1")
  else
     local temp=ngx.req.get_headers()["X-Request-HOP"]
     temp=temp+1
     ngx.req.set_header("X-Request-HOP",temp)
  end
end
return _M
