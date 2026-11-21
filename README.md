# nginx_http_xproxy_module and nginx_stream_xproxy_module

An extended fork of `nginx_http_proxy_module` and `nginx_stream_proxy_module` from nginx 1.24.0.

New features:
- HTTP and stream connections over SOCKS4 and SOCKS5 proxies
- SOCKS5 username/password authentication
- remote DNS through the SOCKS proxy or local DNS resolution
- proxy DNS mode for SOCKS4a

Inspired by [socks-nginx-module](https://github.com/dannote/socks-nginx-module) by Dannote.

## Building

nginx >= **1.24.0** is supported. The current code is tested with nginx 1.30.

```bash
# apt-get install git build-essential zlib1g-dev libpcre3 libpcre3-dev unzip

$ git clone https://github.com/WSandwitch/nginx_xproxy_module

$ cd nginx_dir
$ patch -p1 < /path/to/nginx_xproxy_module/http/patch_1.24.0.patch
# See http://nginx.org/en/docs/configure.html for more configuration options
$ ./configure [other params] --add-dynamic-module=/path/to/nginx_xproxy_module/http --add-dynamic-module=/path/to/nginx_xproxy_module/stream

$ make
# make install
```

The `after_connect_handler` patch is required by the HTTP module.

## Configuring

### xproxy_socks

Context: `http`, `server`, `location` (HTTP); `server` (stream)

Default: `none;`

Enables connections through a SOCKS proxy.

Supported schemes:

- `socks4://` — SOCKS4; local resolve is IPv4-only, proxy resolve uses SOCKS4a
- `socks5://` — SOCKS5
- `socks4a://` — SOCKS4a, always remote DNS
- `socks5h://` — SOCKS5, always remote DNS

SOCKS5 credentials are set in the URL:

```nginx
xproxy_socks socks5://user:password@proxy:1080;
```

SOCKS4 uses the username as USERID; passwords are not supported by SOCKS4.

`xproxy_via` is an alias for `xproxy_socks`.

### xproxy_socks_resolve

Context: `http`, `server`, `location` (HTTP); `main`, `server` (stream)

Default: `proxy;`

- `proxy` — pass the target hostname to the SOCKS proxy (remote DNS)
- `local` — resolve the target locally and pass its IP address

Remote DNS requires a domain-capable SOCKS version: SOCKS4 uses SOCKS4a and SOCKS5 sends the domain address type.

Local resolve currently requires the target to be an IP literal; domain targets in `local` mode are rejected. The SOCKS proxy hostname itself is always resolved locally; configure `resolver` when it is a domain name.

## HTTP

Sample reverse proxy over an authenticated SOCKS5 proxy:

```nginx
location / {
    xproxy_socks socks5://user:password@proxy:1080;
    xproxy_socks_resolve proxy;
    xproxy_pass http://httpbin.org/get;
}
```

Proxy requests to `ipinfo.io` through a local Tor daemon:

```nginx
location /ip {
    xproxy_socks socks5://127.0.0.1:9050;
    xproxy_pass http://ipinfo.io;
}
```

All `ngx_http_proxy_module` directives are supported.

Upstream keepalive is disabled when SOCKS is active, because a SOCKS connection is bound to its original target.

## Stream

Only TCP is supported with SOCKS.

```nginx
stream {
    server {
        listen 127.0.0.1:8080;

        xproxy_socks socks5://user:password@proxy:1080;
        xproxy_socks_resolve proxy;
        xproxy_pass target.example:443;

        xproxy_ssl on;
        xproxy_ssl_server_name on;
    }
}
```

`xproxy_pass` must use an explicit `host:port`. Named upstreams are not supported together with SOCKS, because the SOCKS target would be ambiguous.

`xproxy_ssl` and `xproxy_protocol` are applied after the SOCKS tunnel is established.

## Testing

The repository includes a self-contained SOCKS integration suite:

```bash
python3 tests/socks/run.py \
    --nginx /path/to/nginx \
    --http-module /path/to/ngx_http_xproxy_module.so \
    --stream-module /path/to/ngx_stream_xproxy_module.so \
    --label normal \
    --mode all
```

See `tests/socks/README.md` for normal and ASan build commands, modes, soak
duration and report locations.
