---
name: parsec-lan-signaling
description: Adapt and debug the local Parsec signaling server in this repo (privsvr.py). Use when a Parsec update breaks login, host discovery, or the offer/answer/candex relay; when the patched loader stops starting; when hosts/CA redirect fails; or when re-deriving the binary patch points. Covers re-capturing kessel-api/kessel-ws traffic, updating the relay handlers, and verifying a session end to end.
---

# Parsec LAN signaling

This repo replaces Parsec's cloud signaling so LAN peers can stream without an
account. `privsvr.py` serves the HTTPS API and relays the WebSocket session
setup; media is direct UDP between peers.

## Read first

| file | when |
|---|---|
| `references/protocol.md` | exact API/WS schema, envelope, actions, field names, error codes |
| `references/versioning.md` | per-version adaptation checklist + binary patch rediscovery |
| `scripts/recorder.py` | TLS terminator that logs the real kessel traffic (plaintext) |

## Layout

```
parsec-lab/
  privsvr.py              server: /me, /v2/hosts, WS relay
  install.py              CA + hosts + user.bin + autostart + shortcut
  uninstall.py            reverse of install
  launch-parsec.pyw       start server if needed, then Parsec
  ca.pem ca.key leaf-chain.pem leaf.key
  state.json              host name -> peer id
  skills/parsec-lan-signaling/   this skill
```

## Adapt to a new Parsec build

1. **Identify the loaded module.** `%APPDATA%\Parsec\appdata.json` holds
   `so_name` (e.g. `parsecd-150-105c.dll`). The app's build number also appears in
   the WS query (`build=`) and the `X-Parsec-App-Version` header.
2. **Capture the real flow** with `scripts/recorder.py` (see its header). Point the
   three domains at 127.0.0.1, trust `ca.pem`, restart Parsec, and read the
   captures. You need four samples: `/me`, `/v2/hosts`, host `conn_update`, and a
   client `offer` + `answer` + `candex`.
3. **Diff against `references/protocol.md`.** Update the handlers in
   `privsvr.py` (`api_me`, `api_hosts`, `handle_ws_message`, `route_*`). Keep the
   relay pass-through: you never need to interpret the ICE/AES payload, only route
   by `attempt_id`.
4. **Re-derive the binary patches** if the app no longer boots past login or the
   loader refuses the modified DLL (silent exit code 2). Steps and last-known
   offsets are in `references/versioning.md`.
5. **Verify** with the smoke test below.

## Last verified build (150-105c, loader 17/18)

| target | RVA | bytes |
|---|---|---|
| `parsecd.exe` pinned-cert check `sub_1400066E0` | `0x66E0` | `B8 01 00 00 00 C3` (mov eax,1; ret) |
| client DLL startup state `movabs rax, 0x100000010000000` | `0x37E17` | last imm byte `01` -> `02` (main panel) |

Why the first one: the loader validates the skel DLL's Authenticode leaf key
against six pinned SPKI blobs; a patched DLL has a broken digest, so the check
must return true. The `verified\` copy is only used when running as LocalSystem.

## Failure signatures

| symptom | cause |
|---|---|
| loader exits 2, no window, no log | DLL signature check; patch `sub_1400066E0` |
| login page appears despite the boot patch | state initializer moved/changed; re-find the `movabs` |
| `/me` 401 in app log while using privsvr | privsvr not running or hosts not pointing at it |
| TLS error / no capture | CA not trusted, or cert pinning (new: patch the client) |
| `signal_thread[...] = -6105` | server sent `close` (reason not in the known list) |
| `offer to offline host ... queued for 3s` | host WS not registered; flushes on `conn_update`, else `close/HOST_NOT_FOUND` |
| Computers card stays after the host quits | this build ignores `online:false`; server must omit offline hosts (done in `api_hosts`) |
| `candex for unknown attempt` | attempt id mismatch; strip whitespace/`\r` and compare exact strings |
| session connects, high input lag | host encode, not signaling: check the in-session graph `Host: Video Total` |

## Rules

- Parsec JSON string values can carry a trailing `\r`; strip every string field
  before comparing or routing.
- The server assigns `from`; the client only knows `to` (peer id from
  `/v2/hosts`) and its own `attempt_id`.
- `/v2/hosts` must exclude the requesting device (match `X-Parsec-Device-ID`
  against the host's `conn_update.device_id`) or the UI shows a duplicate of the
  local "This Computer" card.
- `/v2/hosts` must also omit hosts with no live WS connection: the UI renders
  `online:false` as a normal card, so a stale entry looks connectable.
- Media never passes through the server; if the session has no video, the bug is
  in signaling/candidates, not bandwidth.
- Do not "fix" a host that closes its WS right after `conn_update`; it reconnects
  and the offer queue covers the gap.

## Smoke test

```powershell
# host side
Get-Content C:\Users\eater\parsec-lab\privsvr.log -Tail 20 -Wait   # expect "host registered"
# API
python - <<'PY'
import ssl,http.client,json
ctx=ssl.create_default_context(cafile=r'C:\Users\eater\parsec-lab\ca.pem')
c=http.client.HTTPSConnection('kessel-api.parsec.app',443,context=ctx,timeout=8)
c.request('GET','/v2/hosts?mode=desktop',headers={'X-Parsec-Device-ID':'test'})
print(json.loads(c.getresponse().read()))
PY
```

A healthy connect produces, in order: `offer` -> `answer` -> several `candex`
both ways -> `BUD|...` and `[0] FPS:` lines in the client log.
