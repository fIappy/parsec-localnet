# Adapting to a new Parsec build

Work top to bottom; each step has a concrete signal that tells you whether the
next one is needed.

## 0. Identify what changed

| area | where to look | if changed |
|---|---|---|
| loaded module | `%APPDATA%\Parsec\appdata.json` -> `so_name`, `hash` | patches must be re-applied to the new DLL |
| build string | WS query `build=`, header `X-Parsec-App-Version` | informational; the server does not validate it |
| API host/scheme | client URL builder: `"%s%s://%s%s%s"` with `http`/`s`; host `"kessel-api."+env` | update recorder/privsvr expectations |
| WS host | `/me` -> `app_config.ws_host` | update hosts entry / cert SANs |
| WS query | client signal thread `/?session_id=%s&role=%s&version=1&build=%s&sdk_version=%u` | privsvr ignores extra params; only `role`/`session_id` are read |
| actions / fields | capture (step 1) | update the `route_*` handlers |
| host auth (pinning) | recorder fails at TLS with no request logged | patch client TLS verification (harder) |

## 1. Capture the real flow

`scripts/recorder.py` terminates TLS with the lab leaf, logs plaintext, and
forwards to the real service.

```powershell
# 1. trust the lab CA (elevated)
certutil -addstore -f Root C:\Users\eater\parsec-lab\ca.pem
# 2. redirect the three domains (elevated)
#    C:\Windows\System32\drivers\etc\hosts
127.0.0.1 kessel-api.parsec.app
127.0.0.1 kessel-ws-v2.parsec.app
127.0.0.1 public.parsec.app
ipconfig /flushdns
# 3. run the recorder (elevated; port 443)
python C:\Users\eater\parsec-lab\skills\parsec-lan-signaling\scripts\recorder.py --port 443
# 4. restart Parsec and read skills/.../capture/*.log
```

If DNS resolves the hosts to a fake/proxy range (e.g. 198.18.x.x from Clash),
resolve the true IPs over DoH and put them in `REAL_IP` at the top of the
recorder; direct TLS to those IPs with the original SNI works.

If the recorder sees TLS EOF before any request, the build pins certificates.
Fall back to hooking inside the process (`WinHttpWebSocketSend` /
`WinHttpWebSocketReceive`, or the app's JSON serializers) instead of MITM.

`--fake` answers the 101 locally without upstream: useful to observe what the
client sends when no real server is reachable.

## 2. Trigger the interesting traffic

Host registration needs hosting enabled:

```json
// %APPDATA%\Parsec\config.json  (second array element)
"app_host": {"value": true}
```

Restart Parsec; the host opens `role=host` and sends `conn_update`.

A client connect can be forced without touching the UI:

```powershell
Stop-Process -Name parsecd -Force
# add peer_id to config.json, then start parsecd
# {"peer_id": {"value": "<peer id from /v2/hosts>"}}
Start-Process "C:\Program Files\Parsec\parsecd.exe"
```

The startup path reads `peer_id` from config, connects immediately, and deletes
the key. The client must not be running when you edit the file (it rewrites
config on exit).

## 3. Binary patches

### 3a. Loader pinned-cert check (`parsecd.exe`)

Purpose: allow a modified client DLL to load. The loader verifies the DLL's
Authenticode leaf public key against six pinned base64 SPKI strings and exits
silently with code 2 on mismatch.

Rediscover (150-105c: `sub_1400066E0`, RVA `0x66E0`):

1. Imports of interest: `WinVerifyTrust`, `WTHelperProvDataFromStateData`,
   `WTHelperGetProvSignerFromChain`, `WTHelperGetProvCertFromChain`,
   `CryptBinaryToStringW`.
2. Xref `WinVerifyTrust`; the function that calls it three times (verify, then
   re-fetch state, then cleanup), extracts `pCertInfo->SubjectPublicKeyInfo`,
   base64-encodes it, and compares against several long `MIIC...` blobs is the
   pin check.
3. Patch its entry to return true:

```
B8 01 00 00 00 C3        mov eax, 1 ; ret
```

File offset = RVA - section.VirtualAddress + section.PointerToRawData
(`parsecd.exe` `.text`: VA `0x1000`, raw `0x400`; `0x66E0` -> file `0x5AE0`).

This patch also disables the loader's self-check, which only gates the
`verified\` copy used under LocalSystem; normal user runs load the cache DLL
directly.

### 3b. Boot state (`%APPDATA%\Parsec\parsecd-<ver>.dll`)

Purpose: boot into the main panel instead of the login panel when not
authenticated.

Model:

- UI state is a 64-bit qword (150-105c: `qword_1805B7208`), copied from the app
  object every frame by `sub_180034DE0`.
- Bits: `1<<56` login panel, `1<<57` main pages; low bits are tab selection
  (`1<<28` computers, `1<<30` settings, `1<<31` console); `1<<58` is a modal flag.
- The startup path `sub_180037D10` writes `0x100000010000000` (login), then
  `0x200000010000000` after a cached session loads.
- The frame branches on bit 56; forcing the page branch alone shows an empty
  content area because the page draw also tests the panel id.

Rediscover:

1. String `login_pre_frame` -> the login panel tick; the state global is written
   in the same module (`mov qword ptr [rip+...], imm`).
2. In the frame function, `movabs rax, 0x100000010000000` followed by
   `mov [rcx], rax` is the boot state initializer.
3. Patch the immediate's last byte `01` -> `02`.

150-105c: RVA `0x37E17`, file offset `0x37217` in the DLL. Verify with
`48 B8 00 00 00 10 00 00 00 02`.

Restart the app after patching; the loader rewrites `appdata.json` with the new
hash automatically.

## 4. Post-update maintenance

- Parsec's updater can replace the cache DLL; re-apply 3b to the new file.
- Pin a build by setting the config key `app_block_hash` to its SHA-256, or make
  the DLL read-only; both are opt-in.
- Keep `parsecd.exe.orig` / `<dll>.orig` from before patching.

## 5. Non-Windows clients

The lab CA and hosts redirect work the same. macOS specifics:

```bash
curl -k https://kessel-api.parsec.app/ca.pem -o /tmp/ca.pem
sudo security add-trusted-cert -d -p ssl -r trustRoot \
     -k /Library/Keychains/System.keychain /tmp/ca.pem
# no GUI session (SSH): use the user trust domain instead
security add-trusted-cert -p ssl -r trustRoot \
     -k "$HOME/Library/Keychains/login.keychain-db" /tmp/ca.pem
```

The Windows binary patches do not apply. A macOS host works without a login
because `/me` is served locally; if the app shows a login screen, implement
`POST /v2/auth` (see step 1 captures) or reuse an existing session cache.
Certificate pinning in a macOS build would require patching that binary.

## 6. Version log

| build | loader | DLL RVA (boot) | loader RVA (pin) | notes |
|---|---|---|---|---|
| 150-105c | 17/18 | `0x37E17` | `0x66E0` | WS `sdk_version=393216`; verified 2026-11 |
