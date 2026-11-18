# Parsec LAN signaling server

Local replacement for `kessel-api.parsec.app` / `kessel-ws-v2.parsec.app`.
Parsec peers on the LAN signal through this server and then stream directly
(BUD/UDP, AES-GCM). No Parsec account is involved.

## Files

| file | purpose |
|---|---|
| `privsvr.py` | server: HTTPS API (`/me`, `/v2/hosts`, `/events`) + WSS relay (`offer`/`answer`/`candex`/`close`) |
| `install.py` | install on a machine: trust CA, redirect hosts, write `user.bin`, autostart + start server, desktop shortcut |
| `uninstall.py` | remove: stop server, autostart, hosts redirect, CA, shortcut |
| `launch-parsec.pyw` | start server if needed, wait for :443, then start Parsec (used by the shortcut) |
| `gen-certs.py` | generates the lab CA + leaf cert (`ca.pem`, `ca.key`, `leaf-chain.pem`, `leaf.key`); `install.py` runs it on the server when they are missing |
| `ca.pem` | lab root CA — install on every machine that trusts the server (generated) |
| `leaf-chain.pem` / `leaf.key` | TLS cert + key for the three hostnames (generated, server only) |
| `state.json` | host name → peer id (generated on first registration) |
| `codes.json` | real error catalog served at `/data/errors/codes.json` (suppresses the 404 banner) |

All scripts derive their paths from their own location. The folder can be moved.

## Install

Elevated shell. Server machine:

```
python install.py
```

The first run on the server generates the TLS material in place. Copy at least
`ca.pem` to every client machine (or copy the whole folder) so both ends trust
the same CA. `ca.key` / `leaf.key` stay on the server and are git-ignored.

Client machine (server elsewhere):

```
python install.py --server 192.168.1.3
```

Options: `--no-autostart`, `--no-session`, `--no-shortcut`.

Autostart order: SYSTEM scheduled task → per-user logon task → HKCU Run key
(this machine's policy blocks Task Scheduler, so it uses the Run key).

## Uninstall

```
python uninstall.py                 # full removal
python uninstall.py --keep-hosts    # keep the DNS redirect
python uninstall.py --keep-cert     # keep the CA trusted
```

`user.bin`, `config.json` and the patched Parsec binaries are left alone.

## Moving the folder

```
python uninstall.py        # stop + detach old paths
move  C:\path\parsec-lab   C:\new\path\parsec-lab
cd    C:\new\path\parsec-lab
python install.py
```

`install.py` clears the old autostart entry by name and rewrites it with the
new absolute paths; the shortcut is recreated too. No config file holds paths.

## Runtime

- `privsvr.log` — requests, WS frames, relay decisions (created next to the script).
- `state.json` — peer ids per host name, preserved across restarts.

## Parsec-side patches (not part of this folder)

- `C:\Program Files\Parsec\parsecd.exe` RVA `0x66E0` → `B8 01 00 00 00 C3`
- `%APPDATA%\Parsec\parsecd-150-105c.dll` RVA `0x37E17` → boot to main panel

Backups: `parsecd.exe.orig`, `parsecd-150-105c.dll.orig`.

## Elevation and dry run

`install.py` and `uninstall.py` self-elevate (one UAC prompt) when they need the
hosts file or the machine Root store. `--dry-run` prints exactly what would
happen, including the autostart command with absolute paths, and changes nothing:

```
python install.py --dry-run
python install.py --server 192.168.1.3 --dry-run
```

Path check after moving the folder: `--dry-run` output must reference the new
location in `autostart`, `server`, and `shortcut`.

## Skill for future adaptations

`skills/parsec-lan-signaling/` is a discoverable skill (`skill://parsec-lan-signaling`)
that documents how to adapt this stack to a new Parsec build without redoing the
analysis:

- `SKILL.md` — workflow, last-known patch offsets, failure signatures
- `references/protocol.md` — full API/WS schema and relay contract
- `references/versioning.md` — how to re-capture traffic, re-derive the loader
  and boot-state patches, trigger host/client flows, macOS notes
- `scripts/recorder.py` — TLS terminator that logs the real kessel traffic

`install.py` creates a junction `%USERPROFILE%\.agents\skills\parsec-lan-signaling`
pointing at the repo copy (no elevation needed). `uninstall.py` removes it only
when it points into this repo. After moving the folder, run `install.py` again
and the junction is re-pointed automatically.
