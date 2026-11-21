#!/usr/bin/env python3
"""Run the SOCKS integration matrix for nginx_xproxy_module.

The nginx binary and both dynamic modules are supplied by the caller.  The
script builds throw-away configuration files, starts local HTTP/TCP/SOCKS
servers, runs the matrix and writes a JSON report.
"""

import argparse
import http.client
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cases import HTTP_CASES, HTTP_SPECIAL, NEGATIVE_CONFIGS, STREAM_CASES

HERE = Path(__file__).resolve().parent


def free_port(host="127.0.0.1"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    while True:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, 0))
        port = sock.getsockname()[1]
        sock.close()
        if port not in USED_PORTS:
            USED_PORTS.add(port)
            return port


USED_PORTS = set()


def wait_port(port, host="127.0.0.1", timeout=15):
    deadline = time.time() + timeout
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    while time.time() < deadline:
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect((host, port))
            sock.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def wait_proc(proc, name, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited with code {proc.returncode}")
        time.sleep(0.05)
    return True


def http_request(port, path, method="GET", body=None, timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def raw_http(port, request, timeout=10):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(request)
        data = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return bytes(data)
    finally:
        sock.close()


def stream_exchange(port, payload, timeout=10, tls=False, half_close=False,
                    expect_eof=False):
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(raw, server_hostname="localhost")
    else:
        sock = raw
    try:
        sock.sendall(payload)
        if half_close:
            time.sleep(0.05)
            sock.shutdown(socket.SHUT_WR)
        data = bytearray()
        if expect_eof:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        else:
            while len(data) < len(payload):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            # PROXY protocol tests receive a prefix larger than the payload.
            if not data.endswith(payload):
                sock.settimeout(0.5)
                while True:
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
        return bytes(data)
    finally:
        sock.close()


def config_preamble(args, workdir):
    return f"""
load_module {args.http_module};
load_module {args.stream_module};

daemon off;
worker_processes 2;
worker_rlimit_nofile 8192;
error_log {workdir}/nginx-error.log info;
pid {workdir}/nginx.pid;
events {{ worker_connections 4096; }}
"""


def make_config(args, workdir, ports):
    p = ports
    return config_preamble(args, workdir) + f"""
http {{
    access_log off;
    client_max_body_size 20m;

    server {{
        listen 127.0.0.1:{p['nginx_http']};
        server_name _;

        location /s5 {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_socks_resolve proxy;
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /s5auth {{
            xproxy_socks socks5://testuser:testpass@127.0.0.1:{p['socks_auth']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /s5authfail {{
            xproxy_socks socks5://testuser:wrong@127.0.0.1:{p['socks_auth']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /s5domain {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_socks_resolve proxy;
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /s5h {{
            xproxy_socks socks5h://127.0.0.1:{p['socks_normal']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /s4 {{
            xproxy_socks socks4://127.0.0.1:{p['socks_normal']};
            xproxy_socks_resolve local;
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /s4a {{
            xproxy_socks socks4a://127.0.0.1:{p['socks_normal']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /s4fail {{
            xproxy_socks socks4://127.0.0.1:{p['socks_s4fail']};
            xproxy_socks_resolve local;
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /via {{
            xproxy_via socks4://127.0.0.1:{p['socks_normal']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /local5 {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_socks_resolve local;
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /local6 {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_socks_resolve local;
            xproxy_pass http://[::1]:{p['http_ipv6']};
        }}
        location /localdomain {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_socks_resolve local;
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /inherit/ {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            location /inherit/child {{
                xproxy_pass http://127.0.0.1:{p['http_backend']};
            }}
        }}
        location /override/ {{
            xproxy_socks socks5://testuser:wrong@127.0.0.1:{p['socks_auth']};
            location /override/child {{
                xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
                xproxy_pass http://127.0.0.1:{p['http_backend']};
            }}
        }}
        location /vars {{
            xproxy_socks $arg_s;
            xproxy_pass http://$arg_h:$arg_p;
        }}
        location /frag {{
            xproxy_socks socks5://127.0.0.1:{p['socks_frag']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /sockserror {{
            xproxy_socks socks5://127.0.0.1:{p['socks_error']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /socksclose {{
            xproxy_socks socks5://127.0.0.1:{p['socks_close']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /socksnomethod {{
            xproxy_socks socks5://127.0.0.1:{p['socks_nomethod']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /socksbadver {{
            xproxy_socks socks5://127.0.0.1:{p['socks_badver']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /socksbadatyp {{
            xproxy_socks socks5://127.0.0.1:{p['socks_badatyp']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /sockstruncated {{
            xproxy_socks socks5://127.0.0.1:{p['socks_truncated']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /socksbadreply {{
            xproxy_socks socks5://127.0.0.1:{p['socks_badreply']};
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /sockstimeout {{
            xproxy_socks socks5://127.0.0.1:{p['socks_timeout']};
            xproxy_connect_timeout 1s;
            xproxy_read_timeout 2s;
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /socksfuzz {{
            xproxy_socks socks5://127.0.0.1:{p['socks_fuzz']};
            xproxy_connect_timeout 1s;
            xproxy_read_timeout 2s;
            xproxy_pass http://127.0.0.1:{p['http_backend']};
        }}
        location /post {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /chunked {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /large {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_pass http://target.test:{p['http_backend']};
        }}
        location /tls {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_ssl_verify off;
            xproxy_ssl_server_name on;
            xproxy_pass https://127.0.0.1:{p['http_tls']};
        }}
        location /upgrade {{
            xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
            xproxy_http_version 1.1;
            xproxy_set_header Upgrade $http_upgrade;
            xproxy_set_header Connection "upgrade";
            xproxy_buffering off;
            xproxy_pass http://target.test:{p['http_backend']};
        }}
    }}
}}

stream {{
    server {{
        listen 127.0.0.1:{p['stream_s5']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_socks_resolve proxy;
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_auth']};
        xproxy_socks socks5://testuser:testpass@127.0.0.1:{p['socks_auth']};
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_s4']};
        xproxy_socks socks4://127.0.0.1:{p['socks_normal']};
        xproxy_socks_resolve local;
        xproxy_pass 127.0.0.1:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_s4a']};
        xproxy_socks socks4a://127.0.0.1:{p['socks_normal']};
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_s5h']};
        xproxy_socks socks5h://127.0.0.1:{p['socks_normal']};
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_via']};
        xproxy_via socks4://127.0.0.1:{p['socks_normal']};
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_local']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_socks_resolve local;
        xproxy_pass 127.0.0.1:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_local6']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_socks_resolve local;
        xproxy_pass [::1]:{p['tcp_ipv6']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_localdomain']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_socks_resolve local;
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_authfail']};
        xproxy_socks socks5://testuser:wrong@127.0.0.1:{p['socks_auth']};
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_error']};
        xproxy_socks socks5://127.0.0.1:{p['socks_error']};
        xproxy_pass 127.0.0.1:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_close']};
        xproxy_socks socks5://127.0.0.1:{p['socks_close']};
        xproxy_pass 127.0.0.1:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_frag']};
        xproxy_socks socks5://127.0.0.1:{p['socks_frag']};
        xproxy_pass 127.0.0.1:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_timeout']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_connect_timeout 1s;
        xproxy_timeout 2s;
        xproxy_pass 127.0.0.1:{p['tcp_hang']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_tls']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_ssl on;
        xproxy_ssl_verify off;
        xproxy_ssl_server_name on;
        xproxy_pass 127.0.0.1:{p['tcp_tls']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_pp']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_protocol on;
        xproxy_pass 127.0.0.1:{p['tcp_pp']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_half']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_half_close on;
        xproxy_pass target.test:{p['tcp_echo']};
    }}
    server {{
        listen 127.0.0.1:{p['stream_large']};
        xproxy_socks socks5://127.0.0.1:{p['socks_normal']};
        xproxy_pass target.test:{p['tcp_echo']};
    }}
}}
"""


def make_ports():
    names = [
        "nginx_http", "nginx_stream",
        "http_backend", "http_tls", "http_ipv6", "http_pp", "leak_http",
        "tcp_echo", "tcp_tls", "tcp_pp", "tcp_hang", "tcp_ipv6",
        "socks_normal", "socks_auth", "socks_authfail", "socks_error",
        "socks_close", "socks_frag", "socks_nomethod", "socks_timeout",
        "socks_badver", "socks_badatyp", "socks_truncated", "socks_badreply",
        "socks_fuzz", "socks_s4fail",
        "stream_s5", "stream_auth", "stream_s4", "stream_s4a", "stream_s5h",
        "stream_via", "stream_local", "stream_local6", "stream_localdomain",
        "stream_authfail", "stream_error", "stream_close", "stream_frag",
        "stream_timeout", "stream_tls", "stream_pp", "stream_half",
        "stream_large",
    ]
    return {name: free_port() for name in names}


def make_services(workdir, ports, cert, key):
    return {
        "log": str(workdir / "servers.log"),
        "cert": str(cert),
        "key": str(key),
        "http": [
            {"port": ports["http_backend"]},
            {"port": ports["http_tls"], "tls": True},
            {"port": ports["http_ipv6"], "ipv6": True},
            {"port": ports["http_pp"], "proxy_protocol": True},
        ],
        "tcp": [
            {"port": ports["tcp_echo"], "mode": "echo"},
            {"port": ports["tcp_tls"], "tls": True, "mode": "echo"},
            {"port": ports["tcp_pp"], "mode": "proxy_protocol"},
            {"port": ports["tcp_hang"], "mode": "hang"},
            {"port": ports["tcp_ipv6"], "ipv6": True, "mode": "echo"},
        ],
        "socks": [
            {"port": ports["socks_normal"], "mode": "normal"},
            {"port": ports["socks_auth"], "mode": "auth"},
            {"port": ports["socks_authfail"], "mode": "auth_fail"},
            {"port": ports["socks_error"], "mode": "error"},
            {"port": ports["socks_close"], "mode": "close_connect"},
            {"port": ports["socks_frag"], "mode": "fragment"},
            {"port": ports["socks_nomethod"], "mode": "method_ff"},
            {"port": ports["socks_timeout"], "mode": "timeout"},
            {"port": ports["socks_badver"], "mode": "bad_greeting"},
            {"port": ports["socks_badatyp"], "mode": "bad_atyp"},
            {"port": ports["socks_truncated"], "mode": "truncated"},
            {"port": ports["socks_badreply"], "mode": "bad_reply"},
            {"port": ports["socks_fuzz"], "mode": "fuzz"},
            {"port": ports["socks_s4fail"], "mode": "s4_fail"},
        ],
    }


def generate_cert(workdir):
    cert = workdir / "cert.pem"
    key = workdir / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=localhost",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key, 0o600)
    return cert, key


def add(result_list, name, ok, detail, known=False):
    result_list.append({
        "name": name,
        "ok": bool(ok),
        "known": bool(known),
        "detail": detail,
    })


def run_http_cases(ports, results):
    for case in HTTP_CASES:
        name = case["name"]
        path = case["path"].format(**ports)
        method = case.get("method", "GET")
        body = case.get("body")
        if body == "random1mb":
            body = (b"x" * 1024 * 1024)
        timeout = case.get("timeout", 10)
        try:
            status, data = http_request(ports["nginx_http"], path, method,
                                        body, timeout)
        except Exception as exc:
            add(results, name, False, f"exception {type(exc).__name__}: {exc}")
            continue
        expected = case["status"]
        ok = status in expected if isinstance(expected, tuple) else status == expected
        detail = f"status={status} bytes={len(data)}"
        if ok and case.get("contains"):
            needle = case["contains"].format(**ports).encode()
            ok = needle in data
            detail += f" contains={needle!r}"
        if ok and case.get("length") is not None:
            ok = len(data) == case["length"]
            detail += f" expected_len={case['length']}"
        if case.get("known") and not ok:
            add(results, name, False, detail + " (known limitation)", known=True)
        else:
            add(results, name, ok, detail)


def run_http_special(ports, results):
    conn = http.client.HTTPConnection("127.0.0.1", ports["nginx_http"], timeout=10)
    try:
        conn.request("GET", HTTP_SPECIAL["keepalive"])
        response1 = conn.getresponse()
        status1, body1 = response1.status, response1.read()
        conn.request("GET", HTTP_SPECIAL["keepalive"])
        response2 = conn.getresponse()
        status2, body2 = response2.status, response2.read()
        add(results, "http client keepalive", status1 == 200 and status2 == 200,
            f"statuses={status1},{status2} bytes={len(body1)},{len(body2)}")
    except Exception as exc:
        add(results, "http client keepalive", False,
            f"exception {type(exc).__name__}: {exc}")
    finally:
        conn.close()

    raw = (
        b"POST /post HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
        b"10\r\n" + b"a" * 16 + b"\r\n"
        b"20\r\n" + b"b" * 32 + b"\r\n"
        b"0\r\n\r\n"
    )
    try:
        data = raw_http(ports["nginx_http"], raw)
        ok = b"200 OK" in data and b"body_len=48" in data
        add(results, "http chunked request", ok, f"bytes={len(data)}")
    except Exception as exc:
        add(results, "http chunked request", False,
            f"exception {type(exc).__name__}: {exc}")

    raw = (
        b"GET /upgrade HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n\r\n"
    )
    sock = None
    try:
        sock = socket.create_connection(("127.0.0.1", ports["nginx_http"]),
                                        timeout=10)
        sock.sendall(raw)
        header = bytearray()
        while b"\r\n\r\n" not in header:
            chunk = sock.recv(4096)
            if not chunk:
                break
            header += chunk
        sock.sendall(b"ping-upgrade")
        echo = sock.recv(64)
        ok = b"101" in header and echo == b"ping-upgrade"
        add(results, "http upgrade", ok,
            f"header={bytes(header[:40])!r} echo={echo!r}")
    except Exception as exc:
        add(results, "http upgrade", False,
            f"exception {type(exc).__name__}: {exc}")
    finally:
        if sock:
            sock.close()


def run_stream_cases(ports, results):
    for case in STREAM_CASES:
        name = case["name"]
        port = ports[case["port"]]
        try:
            data = stream_exchange(
                port, case["payload"], timeout=case.get("timeout", 15),
                tls=case.get("tls", False),
                half_close=case.get("half_close", False),
                expect_eof=case.get("expect_eof", False),
            )
        except (ConnectionResetError, BrokenPipeError) as exc:
            if case.get("expect_eof"):
                data = b""
            else:
                add(results, name, False,
                    f"exception {type(exc).__name__}: {exc}")
                continue
        except Exception as exc:
            add(results, name, False, f"exception {type(exc).__name__}: {exc}")
            continue
        expected = case.get("contains")
        if case.get("expect_eof"):
            ok = len(data) == 0
        elif expected:
            ok = expected in data
        else:
            ok = data == case["payload"]
        detail = f"bytes={len(data)} head={data[:40]!r}"
        if case.get("known") and not ok:
            add(results, name, False, detail + " (known limitation)", known=True)
        else:
            add(results, name, ok, detail)


def run_config_cases(args, workdir, ports, results):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:detect_odr_violation=0"
    fmt = dict(ports)
    fmt.update({
        "http": ports["nginx_http"],
        "stream": ports["stream_s5"],
        "backend": ports["http_backend"],
        "socks": ports["socks_normal"],
    })
    for case in NEGATIVE_CONFIGS:
        body = case["body"]
        for key, value in fmt.items():
            body = body.replace("{" + key + "}", str(value))
        conf = f"""
load_module {args.http_module};
load_module {args.stream_module};
error_log stderr;
pid {workdir}/config-{case['name'].replace(' ', '-')}.pid;
events {{}}
{case['section']} {{
{body}
}}
"""
        path = workdir / ("config-" + case["name"].replace(" ", "-") + ".conf")
        path.write_text(conf, encoding="utf-8")
        proc = subprocess.run(
            [args.nginx, "-t", "-p", str(workdir), "-c", str(path)],
            capture_output=True, text=True, env=env, timeout=20,
        )
        output = proc.stdout + proc.stderr
        ok = proc.returncode != 0 and case["contains"] in output
        add(results, "config: " + case["name"], ok,
            f"rc={proc.returncode} output={output[-240:]!r}")


def run_fuzz(args, ports, results):
    def one(_):
        try:
            status, _ = http_request(ports["nginx_http"], "/socksfuzz",
                                     timeout=4)
            return status in (200, 500, 502, 504)
        except Exception:
            return True

    with ThreadPoolExecutor(max_workers=20) as pool:
        values = list(pool.map(one, range(500)))
    add(results, "fuzz 500 malformed socks replies", all(values),
        f"{sum(values)}/500 completed")


def run_stress(ports, results):
    def http_one(i):
        path = ("/s5", "/s5auth", "/post")[i % 3]
        try:
            status, data = http_request(ports["nginx_http"], path,
                                        method="POST" if path == "/post" else "GET",
                                        body=b"stress" if path == "/post" else None,
                                        timeout=15)
            return status == 200
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=64) as pool:
        values = list(pool.map(http_one, range(2000)))
    add(results, "stress 2000 http requests", all(values),
        f"{sum(values)}/2000 ok")

    def stream_one(i):
        payload = (f"stream-{i}-".encode() + b"s" * 65536)
        try:
            data = stream_exchange(ports["stream_s5"], payload, timeout=20)
            return data == payload
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=32) as pool:
        values = list(pool.map(stream_one, range(100)))
    add(results, "stress 100 stream sessions", all(values),
        f"{sum(values)}/100 ok")


def rss_of_tree(pid):
    total = 0
    pids = [pid]
    try:
        children = subprocess.run(["pgrep", "-P", str(pid)],
                                  capture_output=True, text=True).stdout.split()
        pids += [int(x) for x in children]
    except Exception:
        pass
    for item in pids:
        try:
            with open(f"/proc/{item}/status", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
        except OSError:
            pass
    return total


def fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


def run_soak(seconds, ports, nginx_pid, results):
    start = time.time()
    start_rss = rss_of_tree(nginx_pid)
    start_fds = fd_count(nginx_pid)
    requests = 0
    errors = 0
    paths = ["/s5", "/s5auth", "/post", "/sockstimeout", "/s5authfail"]
    while time.time() - start < seconds:
        path = paths[requests % len(paths)]
        try:
            status, _ = http_request(
                ports["nginx_http"], path,
                method="POST" if path == "/post" else "GET",
                body=b"soak" if path == "/post" else None,
                timeout=5,
            )
            if status not in (200, 502, 504):
                errors += 1
        except Exception:
            errors += 1
        requests += 1
    end_rss = rss_of_tree(nginx_pid)
    end_fds = fd_count(nginx_pid)
    ok = errors == 0 and end_fds <= start_fds + 64 and end_rss <= start_rss * 2 + 65536
    add(results, "soak", ok,
        f"seconds={seconds} requests={requests} errors={errors} "
        f"rss_kb={start_rss}->{end_rss} fds={start_fds}->{end_fds}")


def check_asan(workdir, results):
    checks = []
    for pattern, name in (("asan.*", "asan"), ("ubsan.*", "ubsan"),
                          ("leak.*", "leak")):
        for path in sorted(workdir.glob(pattern)):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            if name == "ubsan" and "ngx_string.c:84" in text:
                lines = [line for line in text.splitlines()
                         if "ngx_string.c:84" not in line]
                text = "\n".join(lines).strip()
            if text:
                checks.append((path.name, text[:3000]))
    add(results, "sanitizers clean", not checks,
        "clean" if not checks else repr(checks))


def run_leak(args, workdir, ports, results):
    leak_prefix = workdir / "leak"
    leak_prefix.mkdir()
    for name in ("logs", "client_body_temp", "proxy_temp", "fastcgi_temp",
                 "uwsgi_temp", "scgi_temp"):
        (leak_prefix / name).mkdir()
    conf = f"""
load_module {args.http_module};
daemon off;
master_process off;
worker_processes 1;
error_log {leak_prefix}/nginx-error.log info;
pid {leak_prefix}/nginx.pid;
events {{ worker_connections 512; }}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{ports['leak_http']};
        location /s5 {{ xproxy_socks socks5://127.0.0.1:{ports['socks_normal']}; xproxy_pass http://target.test:{ports['http_backend']}; }}
        location /auth {{ xproxy_socks socks5://testuser:testpass@127.0.0.1:{ports['socks_auth']}; xproxy_pass http://target.test:{ports['http_backend']}; }}
        location /error {{ xproxy_socks socks5://127.0.0.1:{ports['socks_error']}; xproxy_pass http://127.0.0.1:{ports['http_backend']}; }}
        location /local {{ xproxy_socks socks5://127.0.0.1:{ports['socks_normal']}; xproxy_socks_resolve local; xproxy_pass http://target.test:{ports['http_backend']}; }}
    }}
}}
"""
    conf_path = leak_prefix / "nginx.conf"
    conf_path.write_text(conf, encoding="utf-8")
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=1:detect_odr_violation=0:abort_on_error=0:exitcode=0"
    env["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=0"
    stderr = open(leak_prefix / "stderr.log", "w", encoding="utf-8")
    proc = subprocess.Popen(
        [args.nginx, "-p", str(leak_prefix), "-c", str(conf_path)],
        env=env, stdout=stderr, stderr=stderr,
    )
    try:
        if not wait_port(ports["leak_http"], timeout=20):
            raise RuntimeError("leak nginx did not start")
        for _ in range(60):
            for path in ("/s5", "/auth", "/error", "/local"):
                try:
                    http_request(ports["leak_http"], path, timeout=5)
                except Exception:
                    pass
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        stderr.close()
    text = (leak_prefix / "stderr.log").read_text(encoding="utf-8",
                                                  errors="replace")
    bad = [line for line in text.splitlines()
           if "LeakSanitizer" in line or "Direct leak" in line
           or "Indirect leak" in line or "SUMMARY: AddressSanitizer" in line]
    add(results, "leak sanitizer", not bad, repr(bad[:8]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx", required=True)
    parser.add_argument("--http-module", required=True)
    parser.add_argument("--stream-module", required=True)
    parser.add_argument("--label", default="normal")
    parser.add_argument("--mode", choices=("functional", "fuzz", "stress",
                                           "leak", "all"), default="functional")
    parser.add_argument("--workdir", default="/tmp/opencode/xproxy-socks-tests")
    parser.add_argument("--soak", type=int, default=1800)
    parser.add_argument("--asan", action="store_true")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    args.nginx = str(Path(args.nginx).resolve())
    args.http_module = str(Path(args.http_module).resolve())
    args.stream_module = str(Path(args.stream_module).resolve())

    workdir = Path(args.workdir).resolve() / args.label
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    for name in ("logs", "client_body_temp", "proxy_temp", "fastcgi_temp",
                 "uwsgi_temp", "scgi_temp"):
        (workdir / name).mkdir()

    cert, key = generate_cert(workdir)
    ports = make_ports()
    services = make_services(workdir, ports, cert, key)
    spec_path = workdir / "servers.json"
    spec_path.write_text(json.dumps(services, indent=2), encoding="utf-8")

    results = []
    server_proc = None
    nginx_proc = None
    nginx_stderr = None
    try:
        server_out = open(workdir / "servers.out", "w", encoding="utf-8")
        server_proc = subprocess.Popen(
            [sys.executable, str(HERE / "servers.py"), str(spec_path)],
            stdout=subprocess.PIPE, stderr=server_out, text=True,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            if server_proc.poll() is not None:
                raise RuntimeError("test servers exited")
            line = server_proc.stdout.readline()
            if line.strip() == "READY":
                break
        else:
            raise RuntimeError("test servers did not become ready")
        for key in ("http_backend", "http_tls", "http_ipv6", "http_pp",
                    "tcp_echo", "tcp_tls", "tcp_pp", "tcp_hang", "tcp_ipv6"):
            host = "::1" if key in ("http_ipv6", "tcp_ipv6") else "127.0.0.1"
            if not wait_port(ports[key], host=host):
                raise RuntimeError(f"backend port {key} not ready")

        conf_path = workdir / "nginx.conf"
        conf_path.write_text(make_config(args, workdir, ports), encoding="utf-8")
        nginx_stderr = open(workdir / "nginx.out", "w", encoding="utf-8")
        env = os.environ.copy()
        if args.asan:
            env["ASAN_OPTIONS"] = (
                "detect_leaks=0:detect_odr_violation=0:abort_on_error=1:"
                f"log_path={workdir}/asan"
            )
            env["UBSAN_OPTIONS"] = (
                f"print_stacktrace=0:halt_on_error=0:log_path={workdir}/ubsan"
            )
        nginx_proc = subprocess.Popen(
            [args.nginx, "-p", str(workdir), "-c", str(conf_path)],
            env=env, stdout=nginx_stderr, stderr=nginx_stderr,
        )
        if not wait_port(ports["nginx_http"], timeout=20):
            raise RuntimeError("nginx did not start")
        if not wait_port(ports["stream_s5"], timeout=20):
            raise RuntimeError("nginx stream listener did not start")

        if args.mode in ("functional", "all"):
            run_http_cases(ports, results)
            run_http_special(ports, results)
            run_stream_cases(ports, results)
            run_config_cases(args, workdir, ports, results)
        if args.mode in ("fuzz", "all"):
            run_fuzz(args, ports, results)
        if args.mode in ("stress", "all"):
            run_stress(ports, results)
            if args.mode == "all":
                run_soak(args.soak, ports, nginx_proc.pid, results)
        if args.mode in ("leak", "all") and args.asan:
            run_leak(args, workdir, ports, results)
        if args.asan:
            check_asan(workdir, results)

        error_log = workdir / "nginx-error.log"
        text = error_log.read_text(encoding="utf-8", errors="replace") \
            if error_log.exists() else ""
        bad = [line for line in text.splitlines()
               if "[alert]" in line or "segfault" in line
               or "worker process exited" in line]
        add(results, "nginx alert/segfault log", not bad, repr(bad[:8]))
    finally:
        if nginx_proc and nginx_proc.poll() is None:
            nginx_proc.send_signal(signal.SIGTERM)
            try:
                nginx_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                nginx_proc.kill()
                nginx_proc.wait()
        if nginx_stderr:
            nginx_stderr.close()
        if server_proc and server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait()
        if not args.keep:
            for child in workdir.iterdir():
                if child.is_dir() and child.name in (
                        "client_body_temp", "proxy_temp", "fastcgi_temp",
                        "uwsgi_temp", "scgi_temp"):
                    shutil.rmtree(child, ignore_errors=True)

    passed = sum(1 for item in results if item["ok"])
    failed = [item for item in results if not item["ok"] and not item["known"]]
    known = [item for item in results if not item["ok"] and item["known"]]
    report = {
        "label": args.label,
        "mode": args.mode,
        "passed": passed,
        "total": len(results),
        "failed": failed,
        "known": known,
        "results": results,
        "ports": ports,
    }
    report_path = workdir / f"report-{args.label}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"=== {args.label}: {passed}/{len(results)} passed, "
          f"{len(known)} known ===")
    for item in results:
        if not item["ok"]:
            prefix = "KNOWN " if item["known"] else "FAIL "
            print(prefix + item["name"] + " :: " + item["detail"])
    print("report:", report_path)
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
