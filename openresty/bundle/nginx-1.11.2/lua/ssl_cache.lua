--两级cache,集群内部用redis作cache,单机nginx用共享内存作cache.

local ssl_sess = require "ngx.ssl.session"
local redis    = require "resty.redis"
local conf     = require "ssl_cache_conf"

local shname = "ssl_cache"  --lua_shared_dict必须配置为ssl_cache
local shdict = ngx.shared[shname]

local ngx_log      = ngx.log
local ngx_timer_at = ngx.timer.at
local ngx_ERR      = ngx.ERR

local key_expire = 60
local redis_network_timeout  = 60  --进行redis交互时,connect read write的timeout

local redis_keepalvie_timeout    = 60 * 60  --与redis长连接保持时间
local redis_keepalvie_connection = 64       --与redis最大长连接数, per worker process

local _M = {
	
}

local function my_lookup_ssl_session_by_id(sess_id)
	local sess = shdict:get(sess_id)
	if sess then
		return sess
	end

	local red, err = redis:new()
	if err then
		ngx_log(ngx_ERR, "failed to new redis instance ", err)
		return nil
	end

	red:set_timeout(redis_network_timeout)

	local ok, err = red:connect(conf.redis_addr.master.ip, conf.redis_addr.master.port)
	if err then
		ok, err = red:connect(conf.redis_addr.slave.ip, conf.redis_addr.slave.port)
		if err then
			ngx_log(ngx_ERR, "redis all down! ", err)
			return nil
		else
			ok, err = red:auth(conf.redis_addr.slave.port)
			if err then
				ngx_log(ngx_ERR, "redis slave authentication failed")
				return nil
			end
		end
	else
		ok, err = red:auth(conf.redis_addr.master.passwd)
		if err then
			ngx_log(ngx_ERR, "redis master authentication failed")
			return nil
		end
	end

	sess, err = red:get(sess_id)
	if not sess then
		ngx_log(ngx_ERR, "redis lookup failed ", err)
		return nil 
	end

	local expire, err = red:ttl(sess_id)
	if err then
		expire = key_expire
	end

	if sess ~= ngx.null then
		shdict:add(sess_id, sess, expire)
	end

	red:set_keepalive(redis_keepalvie_timeout, redis_keepalvie_connection)

	return sess
end

local function my_save_ssl_session_by_id(sess_id, sess)
	shdict:add(sess_id, sess, conf.session_time_out)

	local red, err = redis:new()
	if err then
		return nil, err
	end

	red:set_timeout(redis_network_timeout)

	local ok, err = red:connect(conf.redis_addr.master.ip, conf.redis_addr.master.port)
	if err then
		return nil, err
	end

	ok, err = red:auth(conf.redis_addr.master.passwd)
	if err then
		return nil, err
	end

	ok, err = red:setex(sess_id, conf.session_time_out, sess)
	if err then
		return nil ,err
	end

	return sess, nil
end

local function ssl_session_save(premature, sess_id, sess)
	local sess, err = my_save_ssl_session_by_id(sess_id, sess)
	if not sess then
        if err then
            ngx_log(ngx_ERR, "failed to save the session by ID ", sess_id, ": ", err)
        end
	end
end

function _M.ssl_session_fetch()
	local sess_id, err = ssl_sess.get_session_id()
	if not sess_id then
		return
	end

	local sess, err = my_lookup_ssl_session_by_id(sess_id)
	if not sess then
		if err then
			ngx_log(ngx_ERR, "failed to look up the session by ID ", sess_id, ": ", err)
		end
	end

	local ok, err = ssl_sess.set_serialized_session(sess)
    if not ok then
        ngx_log(ngx_ERR, "failed to set SSL session for ID ", sess_id, ": ", err)
        return
    end
end

function _M.ssl_session_store()
	local sess_id, err = ssl_sess.get_session_id()
	if not sess_id then
		return
	end

	local sess, err = ssl_sess.get_serialized_session()
	if not sess then
		return
	end

	ngx_timer_at(0, ssl_session_save, sess_id, sess)
end


return _M
