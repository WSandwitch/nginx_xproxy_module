/*
 * Copyright (C) WSandwitch
 */


#ifndef _NGX_XPROXY_SOCKS_H_INCLUDED_
#define _NGX_XPROXY_SOCKS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_XPROXY_SOCKS_DEFAULT_PORT       1080
#define NGX_XPROXY_SOCKS_BUF_SIZE           768
#define NGX_XPROXY_SOCKS_REPLY_SIZE         262

#define NGX_XPROXY_SOCKS4_VERSION           0x04
#define NGX_XPROXY_SOCKS5_VERSION           0x05
#define NGX_XPROXY_AUTH_VERSION             0x01

#define NGX_XPROXY_SOCKS_CMD_CONNECT        0x01

#define NGX_XPROXY_SOCKS_ATYP_IPV4          0x01
#define NGX_XPROXY_SOCKS_ATYP_DOMAIN        0x03
#define NGX_XPROXY_SOCKS_ATYP_IPV6          0x04

#define NGX_XPROXY_SOCKS_AUTH_NONE          0x00
#define NGX_XPROXY_SOCKS_AUTH_USERPASS      0x02
#define NGX_XPROXY_SOCKS_AUTH_UNACCEPTABLE  0xff

#define NGX_XPROXY_SOCKS_REPLY_GRANTED      0x5a


typedef struct {
    ngx_array_t                      *lengths;
    ngx_array_t                      *values;
    ngx_str_t                         url;
    unsigned                          used:1;
} ngx_xproxy_socks_cfg_t;


enum {
    NGX_XPROXY_SOCKS_RESOLVE_PROXY = 0,
    NGX_XPROXY_SOCKS_RESOLVE_LOCAL
};


enum {
    NGX_XPROXY_SOCKS_STATE_INIT = 0,
    NGX_XPROXY_SOCKS_STATE_METHOD,
    NGX_XPROXY_SOCKS_STATE_AUTH,
    NGX_XPROXY_SOCKS_STATE_CONNECT,
    NGX_XPROXY_SOCKS_STATE_REPLY4,
    NGX_XPROXY_SOCKS_STATE_DONE,
    NGX_XPROXY_SOCKS_STATE_ERROR
};


typedef struct {
    ngx_uint_t                        version;
    ngx_uint_t                        resolve;
    ngx_uint_t                        state;

    ngx_str_t                         proxy_host;
    in_port_t                         proxy_port;

    ngx_str_t                         target_host;
    in_port_t                         target_port;

    ngx_str_t                         user;
    ngx_str_t                         pass;

    u_char                            out[NGX_XPROXY_SOCKS_BUF_SIZE];
    size_t                            out_len;
    size_t                            out_pos;

    u_char                            in[NGX_XPROXY_SOCKS_REPLY_SIZE];
    size_t                            in_len;
    size_t                            in_need;

    ngx_uint_t                        rep;
    ngx_str_t                         error;

    unsigned                          started:1;
} ngx_xproxy_socks_conn_t;


static ngx_int_t
ngx_xproxy_socks_unescape(ngx_pool_t *pool, ngx_str_t *dst, u_char *src,
    size_t len)
{
    u_char      *p, *d;
    ngx_uint_t   i, h, l;

    dst->data = NULL;
    dst->len = 0;

    if (len == 0) {
        return NGX_OK;
    }

    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    d = p;

    for (i = 0; i < len; i++) {

        if (src[i] != '%') {
            *d++ = src[i];
            continue;
        }

        if (i + 2 >= len) {
            return NGX_ERROR;
        }

        h = src[i + 1];
        l = src[i + 2];

        if (h >= '0' && h <= '9') {
            h -= '0';

        } else if (h >= 'a' && h <= 'f') {
            h = h - 'a' + 10;

        } else if (h >= 'A' && h <= 'F') {
            h = h - 'A' + 10;

        } else {
            return NGX_ERROR;
        }

        if (l >= '0' && l <= '9') {
            l -= '0';

        } else if (l >= 'a' && l <= 'f') {
            l = l - 'a' + 10;

        } else if (l >= 'A' && l <= 'F') {
            l = l - 'A' + 10;

        } else {
            return NGX_ERROR;
        }

        *d++ = (u_char) ((h << 4) | l);
        i += 2;
    }

    dst->data = p;
    dst->len = d - p;

    return NGX_OK;
}


static void
ngx_xproxy_socks_error(ngx_xproxy_socks_conn_t *s, ngx_str_t *error,
    const char *text)
{
    s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
    error->data = (u_char *) text;
    error->len = ngx_strlen(text);
    s->error = *error;
}


static ngx_int_t
ngx_xproxy_socks_parse_url(ngx_pool_t *pool, ngx_str_t *url,
    ngx_uint_t resolve, ngx_xproxy_socks_conn_t *s, ngx_str_t *error)
{
    u_char      *p, *last, *at, *colon;
    size_t       len;
    ngx_str_t    hostport, userinfo, user, pass;
    ngx_url_t    u;
    ngx_uint_t   force_proxy;

    p = url->data;
    len = url->len;
    force_proxy = 0;

    if (len > 10
        && ngx_strncasecmp(p, (u_char *) "socks5h://", 10) == 0)
    {
        s->version = NGX_XPROXY_SOCKS5_VERSION;
        force_proxy = 1;
        p += 10;
        len -= 10;

    } else if (len > 9
               && ngx_strncasecmp(p, (u_char *) "socks5://", 9) == 0)
    {
        s->version = NGX_XPROXY_SOCKS5_VERSION;
        p += 9;
        len -= 9;

    } else if (len > 10
               && ngx_strncasecmp(p, (u_char *) "socks4a://", 10) == 0)
    {
        s->version = NGX_XPROXY_SOCKS4_VERSION;
        force_proxy = 1;
        p += 10;
        len -= 10;

    } else if (len > 9
               && ngx_strncasecmp(p, (u_char *) "socks4://", 9) == 0)
    {
        s->version = NGX_XPROXY_SOCKS4_VERSION;
        p += 9;
        len -= 9;

    } else {
        ngx_xproxy_socks_error(s, error, "invalid socks URL prefix");
        return NGX_ERROR;
    }

    if (force_proxy) {
        if (resolve == NGX_XPROXY_SOCKS_RESOLVE_LOCAL) {
            ngx_xproxy_socks_error(s, error,
                                   "local resolve is not supported "
                                   "for this socks scheme");
            return NGX_ERROR;
        }

        resolve = NGX_XPROXY_SOCKS_RESOLVE_PROXY;
    }

    s->resolve = resolve;

    last = p + len;

    for (at = NULL, colon = p; colon < last; colon++) {
        if (*colon == '@') {
            at = colon;
        }
    }

    user.len = 0;
    pass.len = 0;
    userinfo.len = 0;

    if (at) {
        userinfo.data = p;
        userinfo.len = at - p;
        hostport.data = at + 1;
        hostport.len = last - hostport.data;

        colon = ngx_strlchr(userinfo.data, userinfo.data + userinfo.len, ':');

        if (colon) {
            user.data = userinfo.data;
            user.len = colon - userinfo.data;
            pass.data = colon + 1;
            pass.len = userinfo.data + userinfo.len - pass.data;

        } else {
            user = userinfo;
        }

        if (ngx_xproxy_socks_unescape(pool, &user, user.data, user.len)
            != NGX_OK)
        {
            ngx_xproxy_socks_error(s, error, "invalid socks username");
            return NGX_ERROR;
        }

        if (ngx_xproxy_socks_unescape(pool, &pass, pass.data, pass.len)
            != NGX_OK)
        {
            ngx_xproxy_socks_error(s, error, "invalid socks password");
            return NGX_ERROR;
        }

    } else {
        hostport.data = p;
        hostport.len = len;
    }

    if (hostport.len == 0
        || ngx_strlchr(hostport.data, hostport.data + hostport.len, '/'))
    {
        ngx_xproxy_socks_error(s, error, "invalid socks URL");
        return NGX_ERROR;
    }

    if (user.len > 0xff) {
        ngx_xproxy_socks_error(s, error, "socks username is too long");
        return NGX_ERROR;
    }

    if (pass.len > 0xff) {
        ngx_xproxy_socks_error(s, error, "socks password is too long");
        return NGX_ERROR;
    }

    if (s->version == NGX_XPROXY_SOCKS4_VERSION && pass.len) {
        ngx_xproxy_socks_error(s, error,
                               "socks4 does not support a password");
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = hostport;
    u.default_port = NGX_XPROXY_SOCKS_DEFAULT_PORT;
    u.no_resolve = 1;

    if (ngx_parse_url(pool, &u) != NGX_OK) {
        ngx_xproxy_socks_error(s, error, "invalid socks proxy address");
        return NGX_ERROR;
    }

    if (u.host.len == 0 || u.port == 0) {
        ngx_xproxy_socks_error(s, error, "invalid socks proxy address");
        return NGX_ERROR;
    }

    s->proxy_host = u.host;
    s->proxy_port = u.no_port ? NGX_XPROXY_SOCKS_DEFAULT_PORT : u.port;
    s->user = user;
    s->pass = pass;

    return NGX_OK;
}


static ngx_int_t
ngx_xproxy_socks_check_url(ngx_pool_t *pool, ngx_str_t *url,
    ngx_str_t *error)
{
    ngx_xproxy_socks_conn_t  s;

    ngx_memzero(&s, sizeof(ngx_xproxy_socks_conn_t));

    return ngx_xproxy_socks_parse_url(pool, url,
                                      NGX_XPROXY_SOCKS_RESOLVE_PROXY,
                                      &s, error);
}


static ngx_int_t
ngx_xproxy_socks_build_greeting(ngx_xproxy_socks_conn_t *s)
{
    s->out[0] = NGX_XPROXY_SOCKS5_VERSION;

    if (s->user.len || s->pass.len) {
        s->out[1] = 2;
        s->out[2] = NGX_XPROXY_SOCKS_AUTH_NONE;
        s->out[3] = NGX_XPROXY_SOCKS_AUTH_USERPASS;
        s->out_len = 4;

    } else {
        s->out[1] = 1;
        s->out[2] = NGX_XPROXY_SOCKS_AUTH_NONE;
        s->out_len = 3;
    }

    s->out_pos = 0;
    s->state = NGX_XPROXY_SOCKS_STATE_METHOD;
    s->in_len = 0;
    s->in_need = 2;

    return NGX_OK;
}


static ngx_int_t
ngx_xproxy_socks_build_auth(ngx_xproxy_socks_conn_t *s)
{
    if (s->user.len > 0xff || s->pass.len > 0xff) {
        s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
        ngx_str_set(&s->error, "socks credentials are too long");
        return NGX_ERROR;
    }

    s->out[0] = NGX_XPROXY_AUTH_VERSION;
    s->out[1] = (u_char) s->user.len;

    if (s->user.len) {
        ngx_memcpy(s->out + 2, s->user.data, s->user.len);
    }

    s->out[2 + s->user.len] = (u_char) s->pass.len;

    if (s->pass.len) {
        ngx_memcpy(s->out + 3 + s->user.len, s->pass.data, s->pass.len);
    }

    s->out_len = 3 + s->user.len + s->pass.len;
    s->out_pos = 0;
    s->state = NGX_XPROXY_SOCKS_STATE_AUTH;
    s->in_len = 0;
    s->in_need = 2;

    return NGX_OK;
}


static ngx_int_t
ngx_xproxy_socks_build_connect(ngx_xproxy_socks_conn_t *s, ngx_pool_t *pool)
{
    u_char                  *p, *ip;
    size_t                   len;
    u_short                  port;
    ngx_str_t                host;
    ngx_addr_t               addr;
    ngx_int_t                rc;
    struct sockaddr_in      *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6     *sin6;
#endif

    host = s->target_host;

    if (host.len > 2 && host.data[0] == '[' && host.data[host.len - 1] == ']') {
        host.data++;
        host.len -= 2;
    }

    if (host.len == 0 || host.len > 0xff) {
        s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
        ngx_str_set(&s->error, "invalid socks target host");
        return NGX_ERROR;
    }

    if (s->target_port == 0) {
        s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
        ngx_str_set(&s->error, "invalid socks target port");
        return NGX_ERROR;
    }

    ngx_memzero(&addr, sizeof(ngx_addr_t));

    rc = ngx_parse_addr(pool, &addr, host.data, host.len);

    if (rc == NGX_ERROR) {
        s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
        ngx_str_set(&s->error, "invalid socks target address");
        return NGX_ERROR;
    }

    if (s->version == NGX_XPROXY_SOCKS4_VERSION) {

        p = s->out;
        *p++ = NGX_XPROXY_SOCKS4_VERSION;
        *p++ = NGX_XPROXY_SOCKS_CMD_CONNECT;

        port = htons(s->target_port);
        ngx_memcpy(p, &port, 2);
        p += 2;

        if (rc == NGX_OK) {

            if (addr.sockaddr->sa_family != AF_INET) {
                s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
                ngx_str_set(&s->error,
                            "socks4 requires an IPv4 target");
                return NGX_ERROR;
            }

            sin = (struct sockaddr_in *) addr.sockaddr;
            ngx_memcpy(p, &sin->sin_addr, 4);
            p += 4;

        } else {

            if (s->resolve != NGX_XPROXY_SOCKS_RESOLVE_PROXY) {
                s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
                ngx_str_set(&s->error,
                            "local socks4 resolve requires an IPv4 target");
                return NGX_ERROR;
            }

            *p++ = 0;
            *p++ = 0;
            *p++ = 0;
            *p++ = 1;
        }

        if (s->user.len) {
            ngx_memcpy(p, s->user.data, s->user.len);
            p += s->user.len;
        }

        *p++ = '\0';

        if (rc == NGX_DECLINED) {
            ngx_memcpy(p, host.data, host.len);
            p += host.len;
            *p++ = '\0';
        }

        s->out_len = p - s->out;
        s->out_pos = 0;
        s->state = NGX_XPROXY_SOCKS_STATE_REPLY4;
        s->in_len = 0;
        s->in_need = 8;

        return NGX_OK;
    }

    p = s->out;
    *p++ = NGX_XPROXY_SOCKS5_VERSION;
    *p++ = NGX_XPROXY_SOCKS_CMD_CONNECT;
    *p++ = 0;

    if (rc == NGX_OK) {

        switch (addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            *p++ = NGX_XPROXY_SOCKS_ATYP_IPV6;
            sin6 = (struct sockaddr_in6 *) addr.sockaddr;
            ip = (u_char *) &sin6->sin6_addr;
            ngx_memcpy(p, ip, 16);
            p += 16;
            break;
#endif

        case AF_INET:
            *p++ = NGX_XPROXY_SOCKS_ATYP_IPV4;
            sin = (struct sockaddr_in *) addr.sockaddr;
            ip = (u_char *) &sin->sin_addr;
            ngx_memcpy(p, ip, 4);
            p += 4;
            break;

        default:
            s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
            ngx_str_set(&s->error, "unsupported socks target address");
            return NGX_ERROR;
        }

    } else {
        if (s->resolve != NGX_XPROXY_SOCKS_RESOLVE_PROXY) {
            s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
            ngx_str_set(&s->error,
                        "local socks5 resolve requires an IP target");
            return NGX_ERROR;
        }

        *p++ = NGX_XPROXY_SOCKS_ATYP_DOMAIN;
        *p++ = (u_char) host.len;
        ngx_memcpy(p, host.data, host.len);
        p += host.len;
    }

    port = htons(s->target_port);
    ngx_memcpy(p, &port, 2);
    p += 2;

    len = p - s->out;
    s->out_len = len;
    s->out_pos = 0;
    s->state = NGX_XPROXY_SOCKS_STATE_CONNECT;
    s->in_len = 0;
    s->in_need = 4;

    return NGX_OK;
}


static ngx_int_t
ngx_xproxy_socks_start(ngx_xproxy_socks_conn_t *s, ngx_pool_t *pool,
    ngx_str_t *error)
{
    if (s->version == NGX_XPROXY_SOCKS5_VERSION) {
        return ngx_xproxy_socks_build_greeting(s);
    }

    if (ngx_xproxy_socks_build_connect(s, pool) != NGX_OK) {
        *error = s->error;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_xproxy_socks_init(ngx_xproxy_socks_conn_t *s, ngx_pool_t *pool,
    ngx_str_t *url, ngx_uint_t resolve, ngx_str_t *target_host,
    in_port_t target_port, ngx_str_t *error)
{
    ngx_memzero(s, sizeof(ngx_xproxy_socks_conn_t));

    if (ngx_xproxy_socks_parse_url(pool, url, resolve, s, error)
        != NGX_OK)
    {
        s->error = *error;
        return NGX_ERROR;
    }

    s->target_host = *target_host;
    s->target_port = target_port;
    s->started = 1;

    return ngx_xproxy_socks_start(s, pool, error);
}


static ngx_int_t
ngx_xproxy_socks_reset(ngx_xproxy_socks_conn_t *s, ngx_pool_t *pool,
    ngx_str_t *error)
{
    s->out_len = 0;
    s->out_pos = 0;
    s->in_len = 0;
    s->in_need = 0;
    s->rep = 0;
    s->error.len = 0;
    s->error.data = NULL;
    s->state = NGX_XPROXY_SOCKS_STATE_INIT;

    return ngx_xproxy_socks_start(s, pool, error);
}


static ngx_int_t
ngx_xproxy_socks_send(ngx_xproxy_socks_conn_t *s, ngx_connection_t *c)
{
    ssize_t  n;

    while (s->out_pos < s->out_len) {

        n = c->send(c, s->out + s->out_pos, s->out_len - s->out_pos);

        if (n == NGX_AGAIN) {
            (void) ngx_handle_write_event(c->write, 0);
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
            ngx_str_set(&s->error, "socks send failed");
            return NGX_ERROR;
        }

        if (n == 0) {
            s->state = NGX_XPROXY_SOCKS_STATE_ERROR;
            ngx_str_set(&s->error, "socks send failed");
            return NGX_ERROR;
        }

        s->out_pos += n;
    }

    s->out_len = 0;
    s->out_pos = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_xproxy_socks_parse(ngx_xproxy_socks_conn_t *s, ngx_pool_t *pool,
    ngx_str_t *error)
{
    size_t       need;

    for ( ;; ) {

        if (s->in_len < s->in_need) {
            return NGX_AGAIN;
        }

        switch (s->state) {

        case NGX_XPROXY_SOCKS_STATE_METHOD:

            if (s->in[0] != NGX_XPROXY_SOCKS5_VERSION) {
                ngx_xproxy_socks_error(s, error,
                                       "invalid socks protocol version");
                return NGX_ERROR;
            }

            if (s->in[1] == NGX_XPROXY_SOCKS_AUTH_NONE) {
                s->in_len = 0;
                s->in_need = 0;

                if (ngx_xproxy_socks_build_connect(s, pool) != NGX_OK) {
                    *error = s->error;
                    return NGX_ERROR;
                }

                return NGX_AGAIN;
            }

            if (s->in[1] == NGX_XPROXY_SOCKS_AUTH_USERPASS) {
                if (s->user.len == 0 && s->pass.len == 0) {
                    ngx_xproxy_socks_error(s, error,
                                           "socks proxy requires "
                                           "authentication");
                    return NGX_ERROR;
                }

                s->in_len = 0;
                s->in_need = 0;

                if (ngx_xproxy_socks_build_auth(s) != NGX_OK) {
                    *error = s->error;
                    return NGX_ERROR;
                }

                return NGX_AGAIN;
            }

            ngx_xproxy_socks_error(s, error,
                                   "no acceptable socks authentication method");
            return NGX_ERROR;

        case NGX_XPROXY_SOCKS_STATE_AUTH:

            if (s->in[0] != NGX_XPROXY_AUTH_VERSION || s->in[1] != 0) {
                ngx_xproxy_socks_error(s, error,
                                       "socks authentication failed");
                return NGX_ERROR;
            }

            s->in_len = 0;
            s->in_need = 0;

            if (ngx_xproxy_socks_build_connect(s, pool) != NGX_OK) {
                *error = s->error;
                return NGX_ERROR;
            }

            return NGX_AGAIN;

        case NGX_XPROXY_SOCKS_STATE_REPLY4:

            if ((s->in[0] != 0 && s->in[0] != NGX_XPROXY_SOCKS4_VERSION)
                || s->in[1] != NGX_XPROXY_SOCKS_REPLY_GRANTED)
            {
                s->rep = s->in[1];
                ngx_xproxy_socks_error(s, error, "socks4 connect failed");
                return NGX_ERROR;
            }

            s->state = NGX_XPROXY_SOCKS_STATE_DONE;
            return NGX_OK;

        case NGX_XPROXY_SOCKS_STATE_CONNECT:

            if (s->in[0] != NGX_XPROXY_SOCKS5_VERSION
                || s->in[2] != 0)
            {
                ngx_xproxy_socks_error(s, error, "invalid socks5 reply");
                return NGX_ERROR;
            }

            if (s->in[1] != 0) {
                s->rep = s->in[1];
                ngx_xproxy_socks_error(s, error, "socks5 connect failed");
                return NGX_ERROR;
            }

            if (s->in_need == 4) {

                switch (s->in[3]) {

                case NGX_XPROXY_SOCKS_ATYP_IPV4:
                    s->in_need = 10;
                    break;

                case NGX_XPROXY_SOCKS_ATYP_IPV6:
                    s->in_need = 22;
                    break;

                case NGX_XPROXY_SOCKS_ATYP_DOMAIN:
                    s->in_need = 5;
                    break;

                default:
                    ngx_xproxy_socks_error(s, error,
                                           "unsupported socks5 address type");
                    return NGX_ERROR;
                }

                continue;
            }

            if (s->in_need == 5) {
                need = 7 + s->in[4];

                if (need > sizeof(s->in)) {
                    ngx_xproxy_socks_error(s, error,
                                           "invalid socks5 bound address");
                    return NGX_ERROR;
                }

                s->in_need = need;
                continue;
            }

            s->state = NGX_XPROXY_SOCKS_STATE_DONE;
            return NGX_OK;

        case NGX_XPROXY_SOCKS_STATE_DONE:
            return NGX_OK;

        default:
            ngx_xproxy_socks_error(s, error, "invalid socks state");
            return NGX_ERROR;
        }
    }
}


static ngx_int_t
ngx_xproxy_socks_recv(ngx_xproxy_socks_conn_t *s, ngx_connection_t *c,
    ngx_pool_t *pool, ngx_str_t *error)
{
    ssize_t   n;
    ngx_int_t rc;

    for ( ;; ) {

        if (s->in_len < s->in_need) {

            n = c->recv(c, s->in + s->in_len, s->in_need - s->in_len);

            if (n == NGX_AGAIN) {
                (void) ngx_handle_read_event(c->read, 0);
                return NGX_AGAIN;
            }

            if (n == NGX_ERROR || n == 0) {
                ngx_xproxy_socks_error(s, error, "socks recv failed");
                return NGX_ERROR;
            }

            s->in_len += n;

            if (s->in_len < s->in_need) {
                continue;
            }
        }

        rc = ngx_xproxy_socks_parse(s, pool, error);

        if (rc != NGX_AGAIN) {
            return rc;
        }

        if (s->out_len) {
            return NGX_AGAIN;
        }
    }
}


#endif /* _NGX_XPROXY_SOCKS_H_INCLUDED_ */
