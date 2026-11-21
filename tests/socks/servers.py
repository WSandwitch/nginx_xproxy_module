#!/usr/bin/env python3
"""Local test servers for the SOCKS tests.

The script is started by run.py with a JSON description.  Everything binds to
localhost and is intentionally small; it is not a general purpose SOCKS server.
"""

import argparse
import hashlib
import json
import os
import random
import select
import socket
import ssl
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = b"testuser"
PASS = b"testpass"
LOG_LOCK = threading.Lock()
LOG_PATH = None


def log(**fields):
    if LOG_PATH is None:
        return
    line = json.dumps(fields, sort_keys=True)
    with LOG_LOCK:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()


def recvn(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return bytes(data)


def send_fragmented(conn, data, delay=0.002):
    for value in data:
        conn.sendall(bytes([value]))
        time.sleep(delay)


def relay(client, upstream):
    open_sockets = {client, upstream}
    try:
        while open_sockets:
            readable, _, _ = select.select(list(open_sockets), [], [], 20)
            if not readable:
                break
            for sock in readable:
                try:
                    data = sock.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    open_sockets.discard(sock)
                    other = upstream if sock is client else client
                    if other in open_sockets:
                        try:
                            other.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                    continue
                other = upstream if sock is client else client
                if other not in open_sockets:
                    continue
                try:
                    other.sendall(data)
                except OSError:
                    open_sockets.discard(other)
    finally:
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass


def target_address(host, port):
    name = host.decode("ascii", "replace")
    if name in ("target.test", "localhost"):
        name = "127.0.0.1"
    elif not name:
        name = "127.0.0.1"
    try:
        socket.inet_pton(socket.AF_INET, name)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, name)
        except OSError:
            # Unknown names are deliberately mapped to the HTTP backend so
            # protocol-length tests do not depend on the system resolver.
            name = "127.0.0.1"
    return name, port


def read_socks5_request(conn):
    ver, cmd, rsv, atyp = recvn(conn, 4)
    if atyp == 1:
        host = socket.inet_ntoa(recvn(conn, 4)).encode()
    elif atyp == 3:
        length = recvn(conn, 1)[0]
        host = recvn(conn, length)
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, recvn(conn, 16)).encode()
    else:
        raise ValueError("bad atyp")
    port = struct.unpack("!H", recvn(conn, 2))[0]
    return ver, cmd, rsv, atyp, host, port


def socks5_reply(conn, rep=0, atyp=1, fragment=False):
    if atyp == 4:
        addr = b"\x00" * 16
    elif atyp == 3:
        addr = b"\x09bound.test"
    else:
        addr = b"\x7f\x00\x00\x01"
    reply = b"\x05" + bytes([rep]) + b"\x00" + bytes([atyp]) + addr + b"\x00\x00"
    if fragment:
        send_fragmented(conn, reply)
    else:
        conn.sendall(reply)


def handle_socks5(conn, mode, counter):
    if mode == "close_greeting":
        conn.recv(4096)
        return
    count = recvn(conn, 1)[0]
    methods = recvn(conn, count)
    log(proto=5, mode=mode, stage="greeting", methods=list(methods))

    if mode == "close_method":
        return
    if mode == "method_ff" or (mode == "auth" and 2 not in methods) \
            or (mode != "auth" and 0 not in methods):
        conn.sendall(b"\x05\xff")
        return
    if mode == "bad_greeting":
        conn.sendall(b"\x04\x00")
        return

    if mode in ("auth", "auth_fail", "close_auth"):
        conn.sendall(b"\x05\x02")
        if mode == "close_auth":
            return
        aver = recvn(conn, 1)[0]
        ulen = recvn(conn, 1)[0]
        user = recvn(conn, ulen)
        plen = recvn(conn, 1)[0]
        password = recvn(conn, plen)
        log(proto=5, mode=mode, stage="auth", user=user.decode("latin1"),
            password_len=len(password))
        if aver != 1 or user != USER or password != PASS or mode == "auth_fail":
            conn.sendall(b"\x01\x01")
            return
        conn.sendall(b"\x01\x00")
    else:
        if mode == "fragment":
            send_fragmented(conn, b"\x05\x00")
        else:
            conn.sendall(b"\x05\x00")

    if mode == "close_connect":
        return
    try:
        ver, cmd, rsv, atyp, host, port = read_socks5_request(conn)
    except ValueError:
        socks5_reply(conn, rep=8)
        return
    log(proto=5, mode=mode, stage="request", cmd=cmd, atyp=atyp,
        host=host.decode("latin1", "replace"), port=port)

    if mode == "timeout":
        time.sleep(10)
        return
    if mode == "fuzz":
        rng = random.Random(counter)
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 24)))
        log(proto=5, mode=mode, stage="fuzz", hex=blob.hex())
        if blob:
            conn.sendall(blob)
        return
    if mode == "error":
        socks5_reply(conn, rep=5)
        return
    if mode == "bad_reply":
        conn.sendall(b"\x05\x09\x00\x01\x7f\x00\x00\x01\x00\x00")
        return
    if mode == "bad_atyp":
        socks5_reply(conn, rep=0, atyp=9)
        return
    if mode == "truncated":
        conn.sendall(b"\x05\x00\x00\x01\x7f")
        return
    if cmd != 1:
        socks5_reply(conn, rep=7)
        return

    try:
        upstream = socket.create_connection(target_address(host, port), timeout=5)
    except OSError:
        socks5_reply(conn, rep=5)
        return

    log(proto=5, mode=mode, stage="connected",
        host=host.decode("latin1", "replace"), port=port)
    if mode == "fragment":
        send_fragmented(conn, b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
    elif mode == "ipv6_reply":
        socks5_reply(conn, rep=0, atyp=4)
    elif mode == "domain_reply":
        socks5_reply(conn, rep=0, atyp=3)
    else:
        socks5_reply(conn)
    relay(conn, upstream)


def handle_socks4(conn, mode):
    cmd = recvn(conn, 1)[0]
    port = struct.unpack("!H", recvn(conn, 2))[0]
    ip = recvn(conn, 4)
    user = bytearray()
    while True:
        value = recvn(conn, 1)
        if value == b"\x00":
            break
        user += value

    host = None
    if ip[:3] == b"\x00\x00\x00" and ip[3] != 0:
        name = bytearray()
        while True:
            value = recvn(conn, 1)
            if value == b"\x00":
                break
            name += value
        host = bytes(name)
    else:
        host = socket.inet_ntoa(ip).encode()

    log(proto=4, mode=mode, stage="request", cmd=cmd,
        host=host.decode("latin1", "replace"), port=port,
        user=bytes(user).decode("latin1"))

    if mode == "close_connect":
        return
    if mode == "s4_fail":
        conn.sendall(b"\x00\x5b" + b"\x00" * 6)
        return
    if cmd != 1:
        conn.sendall(b"\x00\x5b" + b"\x00" * 6)
        return

    try:
        upstream = socket.create_connection(target_address(host, port), timeout=5)
    except OSError:
        conn.sendall(b"\x00\x5b" + b"\x00" * 6)
        return

    log(proto=4, mode=mode, stage="connected",
        host=host.decode("latin1", "replace"), port=port)
    conn.sendall(b"\x00\x5a" + b"\x00" * 6)
    relay(conn, upstream)


def socks_client(conn, mode, counter):
    try:
        conn.settimeout(15)
        version = recvn(conn, 1)[0]
        if version == 5:
            if mode.startswith("s4"):
                return
            handle_socks5(conn, mode, counter)
        elif version == 4:
            if mode.startswith("s5"):
                return
            handle_socks4(conn, mode)
    except (EOFError, OSError, ValueError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def start_socks(spec):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", spec["port"]))
    server.listen(256)
    counter = [0]

    def run():
        while True:
            client, _ = server.accept()
            counter[0] += 1
            threading.Thread(target=socks_client,
                             args=(client, spec["mode"], counter[0]),
                             daemon=True).start()

    threading.Thread(target=run, daemon=True).start()
    log(service="socks", port=spec["port"], mode=spec["mode"])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";", 1)[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.read(2)
            return bytes(body)
        size = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(size) if size else b""

    def respond(self):
        body = self.read_body()
        proxy_line = getattr(self, "_proxy_line", b"")
        if self.path.startswith("/large"):
            try:
                count = int(self.path.split("n=", 1)[1].split("&", 1)[0])
            except (IndexError, ValueError):
                count = 1024
            payload = (b"0123456789abcdef" * ((count // 16) + 1))[:count]
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/delay"):
            try:
                delay = int(self.path.split("ms=", 1)[1].split("&", 1)[0])
            except (IndexError, ValueError):
                delay = 100
            time.sleep(delay / 1000.0)
        if self.path.startswith("/reset"):
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if self.path.startswith("/upgrade"):
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            while True:
                data = self.connection.recv(65536)
                if not data:
                    break
                self.connection.sendall(data)
            self.close_connection = True
            return

        result = (
            f"port={self.server.server_port} method={self.command} "
            f"path={self.path} body_len={len(body)} "
            f"sha256={hashlib.sha256(body).hexdigest()} "
            f"proxy={proxy_line.decode('latin1', 'replace').strip()}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if "chunked" in self.path:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(result), 7):
                part = result[i:i + 7]
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)

    do_GET = respond
    do_POST = respond
    do_PUT = respond

    def log_message(self, *args):
        pass


class ProxyProtocolHandler(Handler):
    def handle(self):
        try:
            self._proxy_line = self.rfile.readline(65537)
        except OSError:
            self._proxy_line = b""
        if not self._proxy_line.startswith(b"PROXY "):
            self.close_connection = True
            return
        super().handle()


class IPv6HTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def start_http(spec, tls_context):
    handler = ProxyProtocolHandler if spec.get("proxy_protocol") else Handler
    cls = IPv6HTTPServer if spec.get("ipv6") else ThreadingHTTPServer
    host = "::1" if spec.get("ipv6") else "127.0.0.1"
    server = cls((host, spec["port"]), handler)
    server.daemon_threads = True
    if spec.get("tls"):
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(service="http", port=spec["port"], tls=bool(spec.get("tls")),
        proxy_protocol=bool(spec.get("proxy_protocol")), ipv6=bool(spec.get("ipv6")))


def tcp_client(conn, spec, tls_context):
    try:
        conn.settimeout(30)
        if spec.get("tls"):
            conn = tls_context.wrap_socket(conn, server_side=True)
        mode = spec.get("mode", "echo")
        if mode == "reset":
            return
        if mode == "hang":
            time.sleep(30)
            return
        proxy_line = b""
        if mode == "proxy_protocol":
            data = bytearray()
            while not data.endswith(b"\n") and len(data) < 4096:
                chunk = conn.recv(1)
                if not chunk:
                    return
                data += chunk
            proxy_line = bytes(data)
            conn.sendall(b"PP:" + proxy_line.strip() + b"\n")
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def start_tcp(spec, tls_context):
    server = socket.socket(socket.AF_INET6 if spec.get("ipv6") else socket.AF_INET,
                           socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host = "::1" if spec.get("ipv6") else "127.0.0.1"
    server.bind((host, spec["port"]))
    server.listen(256)

    def run():
        while True:
            conn, _ = server.accept()
            threading.Thread(target=tcp_client,
                             args=(conn, spec, tls_context), daemon=True).start()

    threading.Thread(target=run, daemon=True).start()
    log(service="tcp", port=spec["port"], mode=spec.get("mode", "echo"),
        tls=bool(spec.get("tls")), ipv6=bool(spec.get("ipv6")))


def make_tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("spec")
    args = parser.parse_args()
    with open(args.spec, encoding="utf-8") as f:
        spec = json.load(f)

    global LOG_PATH
    LOG_PATH = spec["log"]
    open(LOG_PATH, "w", encoding="utf-8").close()

    context = make_tls_context(spec["cert"], spec["key"])
    for item in spec.get("http", []):
        start_http(item, context)
    for item in spec.get("tcp", []):
        start_tcp(item, context)
    for item in spec.get("socks", []):
        start_socks(item)

    print("READY", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
