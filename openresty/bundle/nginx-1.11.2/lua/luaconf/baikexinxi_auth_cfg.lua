local cfg = {
    --url_regex: auth url, auth_channel_regex: add channel params to auth server, auth_path: auth path
    { url_regex=[[.*\.m3u8\?]], auth_channel_regex=[[://.*/(.*)/.*\.m3u8\?]], auth_path="/api/stream/auth/play.do"},
}

return cfg
