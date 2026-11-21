"""Functional case matrix.

Strings may contain {http_backend}, {http_tls}, {http_ipv6}, {tcp_echo},
{tcp_tls} and {tcp_pp}; run.py formats them with the allocated ports.
"""

HTTP_CASES = [
    {"name": "socks5 remote domain", "path": "/s5", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "socks5 auth", "path": "/s5auth", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "socks5 auth failure", "path": "/s5authfail", "status": 502},
    {"name": "socks5 proxy resolve domain", "path": "/s5domain", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "socks5h", "path": "/s5h", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "socks4 local ip", "path": "/s4", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "socks4a remote domain", "path": "/s4a", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "socks4 failure reply", "path": "/s4fail", "status": 502},
    {"name": "xproxy_via alias", "path": "/via", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "local resolve ipv4", "path": "/local5", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "local resolve ipv6", "path": "/local6", "status": 200,
     "contains": "port={http_ipv6}"},
    {"name": "local resolve domain is known limitation", "path": "/localdomain",
     "status": 500, "known": True},
    {"name": "nested socks inheritance", "path": "/inherit/child", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "nested socks override", "path": "/override/child", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "variable target", "path": "/vars?s=socks5://127.0.0.1:{socks_normal}&h=target.test&p={http_backend}",
     "status": 200, "contains": "port={http_backend}"},
    {"name": "variable socks", "path": "/vars?s=socks5://127.0.0.1:{socks_normal}&h=127.0.0.1&p={http_backend}",
     "status": 200, "contains": "port={http_backend}"},
    {"name": "short hostname", "path": "/vars?s=socks5://127.0.0.1:{socks_normal}&h=a&p={http_backend}",
     "status": 200, "contains": "port={http_backend}"},
    {"name": "hostname 255", "path": "/vars?s=socks5://127.0.0.1:{socks_normal}&h=" + "a" * 255 + "&p={http_backend}",
     "status": 200, "contains": "port={http_backend}"},
    {"name": "hostname 256", "path": "/vars?s=socks5://127.0.0.1:{socks_normal}&h=" + "a" * 256 + "&p={http_backend}",
     "status": (500, 502)},
    {"name": "empty target host", "path": "/vars?s=socks5://127.0.0.1:{socks_normal}&h=&p={http_backend}",
     "status": 500},
    {"name": "target port zero", "path": "/vars?s=socks5://127.0.0.1:{socks_normal}&h=127.0.0.1&p=0",
     "status": (500, 502)},
    {"name": "fragmented socks replies", "path": "/frag", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "socks error reply", "path": "/sockserror", "status": 502},
    {"name": "socks close mid handshake", "path": "/socksclose", "status": 502},
    {"name": "socks no acceptable method", "path": "/socksnomethod", "status": 502},
    {"name": "socks bad greeting version", "path": "/socksbadver", "status": 502},
    {"name": "socks bad reply atyp", "path": "/socksbadatyp", "status": 502},
    {"name": "socks truncated reply", "path": "/sockstruncated", "status": 502},
    {"name": "socks bad reply", "path": "/socksbadreply", "status": 502},
    {"name": "socks timeout", "path": "/sockstimeout", "status": (502, 504),
     "timeout": 8},
    {"name": "chunked response", "path": "/chunked", "status": 200,
     "contains": "port={http_backend}"},
    {"name": "large response", "path": "/large?n=1048576", "status": 200,
     "length": 1048576},
    {"name": "https target", "path": "/tls", "status": 200,
     "contains": "port={http_tls}"},
    {"name": "post 1mb", "path": "/post", "method": "POST",
     "body": "random1mb", "status": 200, "contains": "body_len=1048576"},
    {"name": "post small", "path": "/post", "method": "POST",
     "body": b"hello", "status": 200, "contains": "body_len=5"},
]

# Paths used by keepalive, chunked request body and upgrade tests.
HTTP_SPECIAL = {
    "keepalive": "/s5",
    "chunked_request": "/post",
    "upgrade": "/upgrade",
}

STREAM_CASES = [
    {"name": "stream socks5 remote domain", "port": "stream_s5",
     "payload": b"stream-socks5\n", "contains": b"stream-socks5\n"},
    {"name": "stream socks5 auth", "port": "stream_auth",
     "payload": b"stream-auth\n", "contains": b"stream-auth\n"},
    {"name": "stream socks4 local ip", "port": "stream_s4",
     "payload": b"stream-socks4\n", "contains": b"stream-socks4\n"},
    {"name": "stream socks4a remote domain", "port": "stream_s4a",
     "payload": b"stream-socks4a\n", "contains": b"stream-socks4a\n"},
    {"name": "stream socks5h", "port": "stream_s5h",
     "payload": b"stream-socks5h\n", "contains": b"stream-socks5h\n"},
    {"name": "stream xproxy_via", "port": "stream_via",
     "payload": b"stream-via\n", "contains": b"stream-via\n"},
    {"name": "stream local resolve ipv4", "port": "stream_local",
     "payload": b"stream-local4\n", "contains": b"stream-local4\n"},
    {"name": "stream local resolve ipv6", "port": "stream_local6",
     "payload": b"stream-local6\n", "contains": b"stream-local6\n"},
    {"name": "stream local resolve domain is known limitation",
     "port": "stream_localdomain", "payload": b"x", "expect_eof": True,
     "known": True},
    {"name": "stream auth failure", "port": "stream_authfail",
     "payload": b"x", "expect_eof": True},
    {"name": "stream socks error", "port": "stream_error",
     "payload": b"x", "expect_eof": True},
    {"name": "stream socks close", "port": "stream_close",
     "payload": b"x", "expect_eof": True},
    {"name": "stream fragmented reply", "port": "stream_frag",
     "payload": b"stream-frag\n", "contains": b"stream-frag\n"},
    {"name": "stream timeout", "port": "stream_timeout",
     "payload": b"x", "expect_eof": True, "timeout": 6},
    {"name": "stream tls target", "port": "stream_tls",
     "payload": b"stream-tls\n", "contains": b"stream-tls\n"},
    {"name": "stream proxy protocol", "port": "stream_pp",
     "payload": b"stream-pp\n", "contains": b"PP:PROXY"},
    {"name": "stream half close", "port": "stream_half",
     "payload": b"stream-half-close\n", "contains": b"stream-half-close\n",
     "half_close": True},
    {"name": "stream large echo", "port": "stream_large",
     "payload": ("stream-large-" + "z" * 1048576).encode(),
     "contains": b"stream-large-"},
]

NEGATIVE_CONFIGS = [
    {"name": "http socks after pass", "section": "http", "body": """
server {
    listen 127.0.0.1:{http};
    location / { xproxy_pass http://127.0.0.1:{backend}; xproxy_socks socks5://127.0.0.1:{socks}; }
}
""", "contains": "must be before xproxy_pass"},
    {"name": "http invalid socks scheme", "section": "http", "body": """
server {
    listen 127.0.0.1:{http};
    location / { xproxy_socks http://127.0.0.1:{socks}; xproxy_pass http://127.0.0.1:{backend}; }
}
""", "contains": "invalid socks URL"},
    {"name": "http duplicate socks", "section": "http", "body": """
server {
    listen 127.0.0.1:{http};
    location / {
        xproxy_socks socks5://127.0.0.1:{socks};
        xproxy_socks socks5://127.0.0.1:{socks};
        xproxy_pass http://127.0.0.1:{backend};
    }
}
""", "contains": "is duplicate"},
    {"name": "stream socks after pass", "section": "stream", "body": """
server {
    listen 127.0.0.1:{stream};
    xproxy_pass 127.0.0.1:{backend};
    xproxy_socks socks5://127.0.0.1:{socks};
}
""", "contains": "must be before xproxy_pass"},
    {"name": "stream invalid socks scheme", "section": "stream", "body": """
server {
    listen 127.0.0.1:{stream};
    xproxy_socks http://127.0.0.1:{socks};
    xproxy_pass 127.0.0.1:{backend};
}
""", "contains": "invalid socks URL"},
    {"name": "stream duplicate socks", "section": "stream", "body": """
server {
    listen 127.0.0.1:{stream};
    xproxy_socks socks5://127.0.0.1:{socks};
    xproxy_socks socks5://127.0.0.1:{socks};
    xproxy_pass 127.0.0.1:{backend};
}
""", "contains": "is duplicate"},
    {"name": "stream pass without port with socks", "section": "stream", "body": """
upstream backend { server 127.0.0.1:{backend}; }
server {
    listen 127.0.0.1:{stream};
    xproxy_socks socks5://127.0.0.1:{socks};
    xproxy_pass backend;
}
""", "contains": "no port in upstream"},
]
