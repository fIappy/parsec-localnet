#!/usr/bin/env python3
"""
Parsec private signaling server (LAN-only).

Serves kessel-api / kessel-ws locally:
  - HTTPS: /me, /v2/hosts, /events, /friend-requests, everything else 404
  - WSS:   role=host registers presence (conn_update), role=client sends
           offer/answer/candex, which this server relays between the two
           connections with the envelope the SDK expects (*_relay actions).

State: peer ids are assigned per host name and persisted to state.json.
"""
import argparse
import base64
import hashlib
import json
import secrets
import os
import random
import socket
import ssl
import struct
import string
import threading
import time
import uuid

LAB = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(LAB, "leaf-chain.pem")
KEY = os.path.join(LAB, "leaf.key")
LOG = os.path.join(LAB, "privsvr.log")
STATE = os.path.join(LAB, "state.json")
USER = {"id": 1, "name": "lan", "warp": False, "team_id": "", "has_avatar": False}
BUILD = "150-105c"

_lock = threading.RLock()
hosts = {}      # peer_id -> {"conn": WSConn, "name":.., "os":.., "platform":.., "mode":..}
clients = {}    # client_id -> WSConn
attempts = {}   # attempt_id -> {"client": client_id, "host": peer_id}
pending = {}    # peer_id -> [{"conn":..,"payload":..,"timer":..}]
QUEUE_GRACE = 3.0      # seconds to wait for a host reconnect before failing the offer
OFFLINE_GRACE = 2.0    # keep a just-disconnected host listed for this long
client_seq = [0]
state = {"names": {}}   # host name -> peer_id


def log(text):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}"
    print(line, flush=True)
    with _lock:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def load_state():
    global state
    if os.path.exists(STATE):
        try:
            state = json.load(open(STATE, encoding="utf-8"))
        except Exception:
            state = {"names": {}}
    state.setdefault("names", {})


def save_state():
    with _lock:
        json.dump(state, open(STATE, "w", encoding="utf-8"), indent=1)


def new_peer_id():
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(27))


def peer_for_name(name):
    with _lock:
        if name not in state["names"]:
            state["names"][name] = new_peer_id()
            save_state()
        return state["names"][name]


def ok_resp(body=None, status="200 OK", ctype="application/json"):
    data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    head = (f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(data)}\r\n"
            "Connection: keep-alive\r\nCache-Control: no-cache, no-store, must-revalidate\r\n\r\n").encode()
    return head + data


class WSConn:
    def __init__(self, sock, role, session):
        self.sock = sock
        self.role = role
        self.session = session
        self.send_lock = threading.Lock()
        self.id = None
        self.peer = None
        self.alive = True

    def send_json(self, obj):
        payload = json.dumps(obj, separators=(",", ":")).encode()
        hdr = bytearray([0x81])
        n = len(payload)
        if n < 126:
            hdr.append(n)
        elif n < 65536:
            hdr.append(126); hdr += struct.pack(">H", n)
        else:
            hdr.append(127); hdr += struct.pack(">Q", n)
        with self.send_lock:
            try:
                self.sock.sendall(bytes(hdr) + payload)
            except Exception as e:
                log(f"send fail {self.id}: {e}")

    def send_pong(self, data):
        hdr = bytearray([0x8A])
        n = len(data)
        if n < 126:
            hdr.append(n)
        elif n < 65536:
            hdr.append(126); hdr += struct.pack(">H", n)
        else:
            hdr.append(127); hdr += struct.pack(">Q", n)
        with self.send_lock:
            try:
                self.sock.sendall(bytes(hdr) + data)
            except Exception:
                pass

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except Exception:
            pass


def dechunk_http(head, body):
    return body


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


def read_body(sock, hdrs, initial):
    n = int(hdrs.get("content-length", "0") or 0)
    body = bytearray(initial)
    while len(body) < n:
        d = sock.recv(min(65536, n - len(body)))
        if not d:
            break
        body += d
    return bytes(body[:n])


def api_me():
    body = {"data": {
        "id": USER["id"], "name": USER["name"], "email": "lan@local", "warp": False, "staff": False,
        "team_id": "", "is_confirmed": True, "team_is_active": False, "is_saml": False,
        "is_gateway_enabled": False, "is_relay_enabled": False, "has_tfa": False,
        "team_enforce_tfa": False, "can_upgrade_session": False, "can_downgrade_session": False,
        "is_client_mode_disabled": False,
        "app_config": {"ws_host": {"value": "kessel-ws-v2.parsec.app"}},
        "app_config_v2": {"ws_host": {"value": "kessel-ws-v2.parsec.app"}},
        "cohort_channel": "release-alpha", "app_ui_channel": "release-ui", "marketing_opt_in": None,
        "session_scopes": ["api.writer"],
        "is_out_of_compliance": False, "is_managed_team_machine": False,
    }}
    return ok_resp(body)


def api_hosts(device_id=""):
    with _lock:
        items = []
        now = time.time()
        for pid, h in hosts.items():
            if not h.get("conn") and now - h.get("offline_since", 0) > OFFLINE_GRACE:
                continue  # offline for good: hide the card instead of showing a dead entry
            if device_id and h.get("device_id") == device_id:
                continue  # self shows up from the local IPC card
            items.append({
                "user": USER, "peer_id": pid, "Connections": None, "game_id": "",
                "description": "", "max_players": 20, "mode": h.get("mode", "desktop"),
                "name": h.get("name", "host"), "event_name": "", "players": 0,
                "public": False, "guest_access": False, "online": bool(h.get("conn")), "self": False,
                "build": BUILD, "OS": h.get("os", "Windows"), "activity": 0,
            })
    return ok_resp({"data": items, "has_more": False})


def handle_http(conn, head, rest):
    start, hdrs = parse_headers(head)
    body = read_body(conn, hdrs, rest)
    try:
        method, path, _ = start.split(" ")
    except ValueError:
        conn.sendall(ok_resp({"error": "bad request"}, "400 Bad Request")); return
    path_only = path.split("?")[0]
    auth = hdrs.get("authorization", "")
    log(f"HTTP {method} {path} host={hdrs.get('host','')[:32]} auth={len(auth)} ua={hdrs.get('user-agent','')[:40]}")
    if path_only == "/me":
        resp = api_me()
    elif path_only == "/me/app-config":
        resp = ok_resp({"data": {"ws_host": {"value": "kessel-ws-v2.parsec.app"}}})
    elif path_only in ("/v2/auth", "/v1/auth"):
        try:
            ab = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            ab = {}
        log(f"auth attempt email={ab.get('email','')[:40]} tfa={bool(ab.get('tfa'))}")
        resp = ok_resp({"session_id": secrets.token_hex(32)})
    elif path_only == "/auth/sessions/elevate":
        log("auth elevate")
        resp = ok_resp({"session_id": secrets.token_hex(32)})
    elif path_only == "/auth/sessions" and method == "DELETE":
        log("auth logout")
        resp = ok_resp(None, "204 No Content")
    elif path_only == "/v2/hosts":
        dev = hdrs.get("x-parsec-device-id", "")
        resp = api_hosts(dev)
        try:
            names = [h["name"] for h in json.loads(resp.split(b"\r\n\r\n", 1)[1])["data"]]
        except Exception:
            names = []
        log(f"hosts -> {names} for device {dev[:12]}")
    elif path_only == "/events":
        resp = ok_resp(None, "204 No Content")
    elif path_only == "/friend-requests":
        resp = ok_resp({"data": []})
    elif path_only == "/data/errors/codes.json":
        try:
            resp = ok_resp(open(os.path.join(LAB, "codes.json"), "rb").read())
        except OSError:
            resp = ok_resp({})
    elif path_only.startswith("/data/notifications/"):
        resp = ok_resp({"display": False})
    elif path_only == "/ca.pem":
        resp = ok_resp(open(os.path.join(LAB, "ca.pem"), "rb").read(), ctype="application/x-pem-file")
    elif path_only.startswith("/data/"):
        resp = ok_resp({"error": "no route"}, "404 Not Found")
    else:
        resp = ok_resp({"error": "no route"}, "404 Not Found")
    conn.sendall(resp)


def feed_frames(buf, data):
    buf += data
    out = []
    while len(buf) >= 2:
        b0, b1 = buf[0], buf[1]
        op = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
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


def _expire_offer(peer, entry):
    with _lock:
        lst = pending.get(peer, [])
        removed = entry in lst
        if removed:
            lst.remove(entry)
            if not lst:
                pending.pop(peer, None)
    if removed:
        log(f"offer expired for offline host {peer}; closing")
        entry["conn"].send_json({"version": 1, "action": "close",
                                 "payload": {"reason": "HOST_NOT_FOUND"}})


def _queue_offer(wsc, peer, payload):
    entry = {"conn": wsc, "payload": payload, "timer": None}
    entry["timer"] = threading.Timer(QUEUE_GRACE, _expire_offer, args=(peer, entry))
    with _lock:
        pending.setdefault(peer, []).append(entry)
    entry["timer"].start()
    log(f"offer to offline host {peer!r}; queued for {QUEUE_GRACE:.0f}s")


def _deliver_offer(wsc, host_peer, payload):
    attempt = payload.get("attempt_id") or uuid.uuid4().hex
    with _lock:
        attempts[attempt] = {"client": wsc.id, "host": host_peer}
        clients[wsc.id] = wsc
    log(f"offer {wsc.id} -> host {host_peer} attempt={attempt!r}")
    h = hosts.get(host_peer)
    if not h or not h.get("conn"):
        return
    h["conn"].send_json({"version": 1, "action": "offer_relay", "payload": {
        "from": wsc.id, "attempt_id": attempt, "data": payload.get("data", {}),
        "is_owner": True, "skip_approval": True,
        "permissions": {"gamepad": True, "keyboard": True, "mouse": True},
        "user": {"name": USER["name"], "id": USER["id"], "has_avatar": False},
    }})


def route_offer(wsc, payload):
    target = payload.get("to", "")
    with _lock:
        host = hosts.get(target)
    if not host or host.get("conn") is None:
        _queue_offer(wsc, target, payload)
        return
    _deliver_offer(wsc, target, payload)


def route_answer(wsc, payload):
    attempt = payload.get("attempt_id", "")
    with _lock:
        a = attempts.get(attempt)
        client = clients.get(a["client"]) if a else None
    if not client:
        log(f"answer for unknown attempt {attempt!r}")
        return
    log(f"answer {wsc.id} -> {a['client']} attempt={attempt[:8]} approved={payload.get('approved')}")
    client.send_json({"version": 1, "action": "answer_relay", "payload": {
        "from": wsc.id,
        "attempt_id": attempt,
        "data": payload.get("data", {}),
        "approved": payload.get("approved", True),
    }})


def route_candex(wsc, payload):
    attempt = payload.get("attempt_id", "")
    with _lock:
        a = attempts.get(attempt)
        target = None
        if a:
            target = (hosts.get(a["host"], {}).get("conn") if wsc.role == "client"
                      else clients.get(a["client"]))
    if not target:
        with _lock:
            keys = list(attempts.keys())
        log(f"candex for unknown attempt {attempt!r} from {wsc.id}; keys={keys}")
        return
    target.send_json({"version": 1, "action": "candex_relay", "payload": {
        "from": wsc.id, "attempt_id": attempt, "data": payload.get("data", {}),
    }})


def route_close(wsc, payload):
    attempt = payload.get("attempt_id", "")
    with _lock:
        a = attempts.get(attempt)
        target = None
        if a:
            target = (hosts.get(a["host"], {}).get("conn") if wsc.role == "client"
                      else clients.get(a["client"]))
    if target:
        target.send_json({"version": 1, "action": "close",
                          "payload": {"reason": payload.get("reason", "")}})
    log(f"close attempt={attempt[:8]} reason={payload.get('reason')!r}")


def ws_session(conn, role, session):
    wsc = WSConn(conn, role, session)
    if role == "client":
        with _lock:
            client_seq[0] += 1
            wsc.id = f"lan{client_seq[0]}"
    else:
        wsc.id = session
    buf = bytearray()
    try:
        while wsc.alive:
            d = conn.recv(65536)
            if not d:
                log(f"ws {wsc.id or wsc.role} EOF from peer")
                break
            frames, buf = feed_frames(buf, d)
            for op, pl in frames:
                log(f"frame {wsc.role} op={op} len={len(pl)}")
                if op == 0x8:
                    wsc.alive = False
                    break
                if op == 0x9:
                    wsc.send_pong(pl)
                    continue
                if op == 0xA:
                    continue
                if op not in (0x1, 0x2):
                    continue
                try:
                    msg = json.loads(pl.decode("utf-8"))
                except Exception:
                    log(f"bad frame from {wsc.id}: {pl[:80]!r}")
                    continue
                handle_ws_message(wsc, msg)
    except socket.timeout:
        log(f"ws {wsc.id} idle timeout ({wsc.role})")
    except Exception as e:
        log(f"ws {wsc.id} error: {type(e).__name__}: {e}")
    finally:
        cleanup(wsc)


def handle_ws_message(wsc, msg):
    action = (msg.get("action", "") or "").strip()
    payload = msg.get("payload", {}) or {}
    payload = {k: (v.strip() if isinstance(v, str) else v) for k, v in payload.items()}
    if action == "conn_update":
        name = payload.get("name", "host")
        pid = peer_for_name(name)
        wsc.id = pid
        with _lock:
            hosts[pid] = {"conn": wsc, "name": name, "os": payload.get("os", "Windows"),
                          "platform": payload.get("platform", "windows"),
                          "mode": payload.get("mode", "desktop"),
                          "device_id": payload.get("device_id", ""),
                          "offline_since": 0}
        log(f"host registered {name} peer={pid} dev={payload.get('device_id','')[:12]} os={payload.get('os')} mode={payload.get('mode')}")
        with _lock:
            queued = pending.pop(pid, [])
        for entry in queued:
            entry["timer"].cancel()
            log(f"flushing queued offer to {name}")
            _deliver_offer(entry["conn"], pid, entry["payload"])
        return
    if wsc.role == "host":
        if action in ("answer", "answer_relay"):
            route_answer(wsc, payload)
        elif action in ("candex", "candex_relay"):
            route_candex(wsc, payload)
        elif action == "close":
            route_close(wsc, payload)
        else:
            log(f"host unhandled action {action}")
        return
    # client role
    if action in ("offer", "offer_relay"):
        wsc.id = wsc.id or f"c{uuid.uuid4().hex[:8]}"
        with _lock:
            clients[wsc.id] = wsc
        route_offer(wsc, payload)
    elif action in ("candex", "candex_relay"):
        route_candex(wsc, payload)
    elif action == "close":
        route_close(wsc, payload)
    else:
        log(f"client unhandled action {action}")


def cleanup(wsc):
    with _lock:
        if wsc.role == "host" and wsc.id in hosts and hosts[wsc.id]["conn"] is wsc:
            name = hosts[wsc.id]["name"]
            hosts[wsc.id]["conn"] = None
            hosts[wsc.id]["offline_since"] = time.time()
            log(f"host offline {name}")
        for cid, c in list(clients.items()):
            if c is wsc:
                del clients[cid]
        for peer, lst in list(pending.items()):
            keep = [e for e in lst if e["conn"] is not wsc]
            for e in lst:
                if e["conn"] is wsc:
                    e["timer"].cancel()
            if keep:
                pending[peer] = keep
            else:
                pending.pop(peer, None)
    wsc.close()


def read_http_request(conn):
    head, rest = read_until(conn, b"\r\n\r\n")
    return head, rest


def serve(conn, addr):
    try:
        conn.settimeout(300)
        head, rest = read_http_request(conn)
        if not head:
            return
        start, hdrs = parse_headers(head)
        if hdrs.get("upgrade", "").lower() == "websocket":
            key = hdrs.get("sec-websocket-key", "")
            acc = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {acc}\r\n\r\n").encode())
            path = start.split(" ")[1]
            q = {}
            if "?" in path:
                for kv in path.split("?", 1)[1].split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        q[k] = v
            role = q.get("role", "client")
            session = q.get("session_id", "") or f"{role}-{uuid.uuid4().hex[:8]}"
            log(f"WS {role} session={session[:12]} from={addr[0]}")
            conn.settimeout(300)
            ws_session(conn, role, session)
        else:
            handle_http(conn, head, rest)
            # keep-alive: continue serving requests on the same connection
            while True:
                head, rest = read_until(conn, b"\r\n\r\n")
                if not head:
                    break
                handle_http(conn, head, rest)
    except Exception as e:
        log(f"conn {addr}: {type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=443)
    args = ap.parse_args()
    load_state()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(64)
    log(f"private signaling server on :{args.port} state={STATE}")

    def accept(raw, addr):
        try:
            raw.settimeout(20)
            tls = ctx.wrap_socket(raw, server_side=True)
        except Exception as e:
            log(f"tls {addr}: {type(e).__name__}: {e}")
            try:
                raw.close()
            except Exception:
                pass
            return
        serve(tls, addr)

    while True:
        raw, addr = srv.accept()
        threading.Thread(target=accept, args=(raw, addr), daemon=True).start()


if __name__ == "__main__":
    main()
