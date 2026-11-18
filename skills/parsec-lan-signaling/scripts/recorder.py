#!/usr/bin/env python3
"""
TLS terminator / recorder for the Parsec signaling endpoints.

Record mode (default): terminates TLS with the lab leaf, logs plaintext HTTP and
WebSocket frames, and forwards to the real service (direct IP map, else the
local HTTP proxy).

Fake mode (--fake): answers the WebSocket 101 locally and logs whatever the
client sends, without any upstream. Use it to observe a client that has no
reachable server.

Setup:
  1. certutil -addstore -f Root <repo>/ca.pem
  2. hosts: 127.0.0.1 kessel-api.parsec.app kessel-ws-v2.parsec.app public.parsec.app
  3. python recorder.py --port 443
  4. restart Parsec; captures land in ./capture/

Certs are looked up next to this script and up to three parent directories
(skills/<name>/scripts -> repo root).
"""
import argparse
import base64
import datetime
import gzip
import hashlib
import os
import socket
import ssl
import struct
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.join(HERE, "capture")

# Real endpoints, resolved over DoH (update when the CDN changes).
REAL_IP = {
    "kessel-api.parsec.app": "104.18.1.181",
    "kessel-ws-v2.parsec.app": "104.18.1.181",
    "public.parsec.app": "104.18.1.181",
}
PROXY = ("127.0.0.1", 7897)
FAKE = False
_lock = threading.Lock()
_seq = [0]


def find(*names):
    for name in names:
        for depth in range(4):
            p = os.path.abspath(os.path.join(HERE, *([os.pardir] * depth), name))
            if os.path.exists(p):
                return p
    return None


CERT = find("leaf-chain.pem")
KEY = find("leaf.key")


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def log(text, path=None):
    with _lock:
        with open(path or os.path.join(CAP, "recorder.log"), "a", encoding="utf-8") as f:
            f.write(f"[{now()}] {text}\n")


class Tee:
    def __init__(self, tag):
        os.makedirs(CAP, exist_ok=True)
        with _lock:
            _seq[0] += 1
            n = _seq[0]
        self.path = os.path.join(CAP, f"{time.strftime('%H%M%S')}_{n:04d}_{tag}.log")
        self.f = open(self.path, "wb")

    def record(self, dirn, data):
        self.f.write(f"\n[{now()}] {dirn} {len(data)} bytes\n".encode())
        self.f.write(data if len(data) <= 4_000_000 else data[:4_000_000] + b"\n...[truncated]")
        self.f.flush()

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


def upstream_connect(host, port=443):
    ip = REAL_IP.get(host)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    if ip:
        raw = socket.create_connection((ip, port), timeout=10)
        return ctx.wrap_socket(raw, server_hostname=host)
    raw = socket.create_connection(PROXY, timeout=15)
    raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        d = raw.recv(4096)
        if not d:
            raise ConnectionError("proxy closed during CONNECT")
        resp += d
    if b" 200 " not in resp.split(b"\r\n", 1)[0]:
        raw.close()
        raise ConnectionError(f"CONNECT rejected: {resp.split(b'\r\n')[0]!r}")
    return ctx.wrap_socket(raw, server_hostname=host)


def read_until(sock, marker, limit=256 * 1024):
    buf = b""
    while marker not in buf:
        d = sock.recv(8192)
        if not d:
            return buf, b""
        buf += d
        if len(buf) > limit:
            raise ValueError("header too large")
    head, rest = buf.split(marker, 1)
    return head + marker, rest


def parse_headers(raw):
    lines = raw.decode("latin1").split("\r\n")
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs


def read_chunked(sock, initial):
    buf = bytearray(initial)
    pos = 0
    while True:
        while buf.find(b"\r\n", pos) < 0:
            d = sock.recv(65536)
            if not d:
                return bytes(buf)
            buf += d
        i = buf.index(b"\r\n", pos)
        try:
            size = int(buf[pos:i].split(b";")[0], 16)
        except ValueError:
            return bytes(buf)
        end = i + 2 + size
        while len(buf) < end + 2:
            d = sock.recv(65536)
            if not d:
                return bytes(buf)
            buf += d
        pos = end + 2
        if size == 0:
            return bytes(buf[:pos])


def read_body(sock, hdrs, initial):
    if "chunked" in hdrs.get("transfer-encoding", "").lower():
        return read_chunked(sock, initial)
    n = int(hdrs.get("content-length", "0") or 0)
    body = bytearray(initial)
    while len(body) < n:
        d = sock.recv(min(65536, n - len(body)))
        if not d:
            break
        body += d
    return bytes(body[:n])


def dechunk(raw):
    out = bytearray()
    pos = 0
    while True:
        i = raw.find(b"\r\n", pos)
        if i < 0:
            return bytes(out)
        try:
            size = int(raw[pos:i].split(b";")[0], 16)
        except ValueError:
            return bytes(out)
        start = i + 2
        out += raw[start:start + size]
        pos = start + size + 2
        if size == 0:
            return bytes(out)


def pretty_response(raw):
    head, sep, body = raw.partition(b"\r\n\r\n")
    low = head.lower()
    try:
        if b"content-encoding: gzip" in low and body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
        elif b"transfer-encoding: chunked" in low:
            body = dechunk(body)
    except Exception:
        pass
    return head + sep + body


def feed_frames(buf, data):
    buf += data
    out = []
    while len(buf) >= 2:
        b0, b1 = buf[0], buf[1]
        op, masked, ln = b0 & 0x0F, b1 & 0x80, b1 & 0x7F
        off = 2
        if ln == 126:
            if len(buf) < 4:
                break
            ln = struct.unpack(">H", buf[2:4])[0]
            off = 4
        elif ln == 127:
            if len(buf) < 10:
                break
            ln = struct.unpack(">Q", buf[2:10])[0]
            off = 10
        mk = b""
        if masked:
            if len(buf) < off + 4:
                break
            mk = buf[off:off + 4]
            off += 4
        if len(buf) < off + ln:
            break
        pl = buf[off:off + ln]
        if masked:
            pl = bytes(c ^ mk[i % 4] for i, c in enumerate(pl))
        out.append((op, pl))
        del buf[:off + ln]
    return out, buf


def log_frame(tee, dirn, op, payload):
    if op in (0x9, 0xA):
        tee.record(f"{dirn} ping/pong op={op}", payload)
        return
    try:
        tee.record(f"{dirn} frame op={op}", payload.decode("utf-8").encode())
    except UnicodeDecodeError:
        tee.record(f"{dirn} bin op={op}", payload)


def ws_conn(client, host, head, rest):
    if FAKE:
        _, hdrs = parse_headers(head)
        key = hdrs.get("sec-websocket-key", "")
        acc = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        client.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {acc}\r\n\r\n").encode())
        log(f"fake ws {head.split(b' ')[1][:120]!r}", os.path.join(CAP, "ws_fake.log"))
        tee = Tee(host.replace(".", "_")[:48] + "_ws_fake")
        buf = bytearray()
        frames, buf = feed_frames(buf, rest) if rest else ([], buf)
        for op, pl in frames:
            log_frame(tee, "C->S", op, pl)
        while True:
            d = client.recv(65536)
            if not d:
                break
            frames, buf = feed_frames(buf, d)
            for op, pl in frames:
                log_frame(tee, "C->S", op, pl)
        tee.close()
        return

    tee = Tee(host.replace(".", "_")[:48] + "_ws")
    tee.record("C->S", head)
    up = upstream_connect(host)
    up.sendall(head)
    rhead, rrest = read_until(up, b"\r\n\r\n")
    if not rhead:
        up.close()
        tee.close()
        return
    tee.record("S->C", rhead)
    client.sendall(rhead + rrest)

    stop = threading.Event()

    def pump(src, dst, dirn, initial):
        buf = bytearray()
        frames, buf = feed_frames(buf, initial) if initial else ([], buf)
        for op, pl in frames:
            log_frame(tee, dirn, op, pl)
        try:
            while not stop.is_set():
                d = src.recv(65536)
                if not d:
                    break
                dst.sendall(d)
                frames, buf = feed_frames(buf, d)
                for op, pl in frames:
                    log_frame(tee, dirn, op, pl)
        except Exception as e:
            log(f"pump {dirn} {host}: {e}", os.path.join(CAP, "errors.log"))
        finally:
            stop.set()

    threading.Thread(target=pump, args=(client, up, "C->S", rest), daemon=True).start()
    threading.Thread(target=pump, args=(up, client, "S->C", rrest), daemon=True).start()
    stop.wait(6 * 3600)
    for s in (up, client):
        try:
            s.close()
        except Exception:
            pass
    tee.close()


def http_conn(client, host, head, rest):
    _, hdrs = parse_headers(head)
    body = read_body(client, hdrs, rest)
    tee = Tee(host.replace(".", "_")[:48])
    tee.record("C->S", head + body)
    up = upstream_connect(host)
    try:
        up.sendall(head + body)
        rhead, rrest = read_until(up, b"\r\n\r\n")
        if not rhead:
            return
        _, rh = parse_headers(rhead)
        rb = read_body(up, rh, rrest)
        client.sendall(rhead + rb)
        tee.record("S->C", pretty_response(rhead + rb))
    finally:
        try:
            up.close()
        except Exception:
            pass
        tee.close()


def serve(conn, addr):
    try:
        conn.settimeout(300)
        while True:
            head, rest = read_until(conn, b"\r\n\r\n")
            if not head:
                return
            _, hdrs = parse_headers(head)
            host = hdrs.get("host", "").split(":")[0]
            if not host:
                return
            if hdrs.get("upgrade", "").lower() == "websocket":
                ws_conn(conn, host, head, rest)
                return
            http_conn(conn, host, head, rest)
    except Exception as e:
        log(f"conn {addr}: {type(e).__name__}: {e}", os.path.join(CAP, "errors.log"))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    global FAKE
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--fake", action="store_true", help="answer WS locally, no upstream")
    args = ap.parse_args()
    FAKE = args.fake

    if not CERT or not KEY:
        raise SystemExit("leaf-chain.pem / leaf.key not found (looked next to the script and parents)")

    os.makedirs(CAP, exist_ok=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(64)
    print(f"recorder :{args.port} fake={FAKE} cert={CERT} out={CAP}", flush=True)

    def accept(raw, addr):
        try:
            raw.settimeout(20)
            tls = ctx.wrap_socket(raw, server_side=True)
        except Exception as e:
            log(f"tls {addr}: {type(e).__name__}: {e}", os.path.join(CAP, "errors.log"))
            try:
                raw.close()
            except Exception:
                pass
            return
        threading.Thread(target=serve, args=(tls, addr), daemon=True).start()

    while True:
        raw, addr = srv.accept()
        threading.Thread(target=accept, args=(raw, addr), daemon=True).start()


if __name__ == "__main__":
    main()
