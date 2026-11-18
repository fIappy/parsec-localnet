#!/usr/bin/env python3
"""
Install the Parsec LAN signaling setup on this machine.

Relocatable: every path is derived from this file's location, so moving the
folder and re-running install.py updates all references (autostart, shortcut).

  python install.py                         # server machine, 127.0.0.1
  python install.py --server 192.168.1.3    # client machine pointing at a LAN server
  python install.py --no-autostart --no-session

Needs an elevated shell (hosts file + machine Root store).
"""
import argparse
import ctypes
import ctypes.wintypes as w
import json
import os
import random
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
CA = os.path.join(ROOT, "ca.pem")
CERT_FILES = ["ca.pem", "ca.key", "leaf-chain.pem", "leaf.key"]
GEN_CERTS = os.path.join(ROOT, "gen-certs.py")
SVR = os.path.join(ROOT, "privsvr.py")
LAUNCH = os.path.join(ROOT, "launch-parsec.pyw")
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
APPDATA = os.path.join(os.environ["APPDATA"], "Parsec")
DOMAINS = ["kessel-api.parsec.app", "kessel-ws-v2.parsec.app", "public.parsec.app"]
MARK = "# parsec-lan"
TASK = "Parsec LAN Signaling"
RUNKEY = "ParsecLanSignaling"
LNK = os.path.join(os.environ["USERPROFILE"], "Desktop", "Parsec (LAN).lnk")
PARSEC = r"C:\Program Files\Parsec\parsecd.exe"
SKILL_NAME = "parsec-lan-signaling"
SKILL_SRC = os.path.join(ROOT, "skills", SKILL_NAME)
SKILL_DST = os.path.join(os.environ["USERPROFILE"], ".agents", "skills", SKILL_NAME)


def pythonw():
    exe = sys.executable
    cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return cand if os.path.exists(cand) else exe


def run(cmd, quiet=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not quiet and r.returncode:
        print(r.stdout, r.stderr)
    return r


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


def elevate(argv):
    params = " ".join(f'"{a}"' for a in [os.path.abspath(__file__)] + argv)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, ROOT, 1)
    if rc <= 32:
        sys.exit("elevation failed (UAC declined)")


def listening(port=443):
    import socket
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ensure_certs():
    missing = [f for f in CERT_FILES if not os.path.exists(os.path.join(ROOT, f))]
    if not missing:
        return
    print(f"  certs     : generating ({', '.join(missing)} missing)")
    r = run([sys.executable, GEN_CERTS])
    if r.returncode:
        sys.exit(f"certificate generation failed: {r.stderr.strip()}")


def install_ca():
    r = run(["certutil", "-addstore", "-f", "Root", CA])
    ok = r.returncode == 0 or "already" in (r.stdout + r.stderr).lower()
    print("  CA        :", "ok" if ok else "FAILED")
    return ok


def write_hosts(server):
    with open(HOSTS, encoding="utf-8", errors="ignore") as f:
        lines = [ln.rstrip("\r\n") for ln in f]
    lines = [ln for ln in lines if MARK not in ln]
    lines += [f"{server} {d} {MARK}" for d in DOMAINS]
    with open(HOSTS, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    run(["ipconfig", "/flushdns"])
    print(f"  hosts     : {server} -> {len(DOMAINS)} domains")


def dpapi(data: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", w.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    inp = BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())
    return ctypes.string_at(out.pbData, out.cbData)


def write_session():
    os.makedirs(APPDATA, exist_ok=True)
    path = os.path.join(APPDATA, "user.bin")
    if os.path.exists(path) and os.path.getsize(path) > 0:
        print("  user.bin  : kept")
        return
    session = "".join(random.choice("0123456789abcdef") for _ in range(64))
    with open(path, "wb") as f:
        f.write(dpapi(json.dumps({"session_id": session}).encode()))
    print("  user.bin  : created", session[:8] + "...")


def enable_host():
    p = os.path.join(APPDATA, "config.json")
    if not os.path.exists(p):
        return
    try:
        j = json.load(open(p, encoding="utf-8"))
        j[1]["app_host"] = {"value": True}
        json.dump(j, open(p, "w", encoding="utf-8"), indent="\t")
        print("  app_host  : true")
    except Exception as e:
        print("  app_host  : skipped", e)


def clear_autostart():
    run(["schtasks", "/Delete", "/TN", TASK, "/F"])
    run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", RUNKEY, "/f"])


def install_autostart():
    cmd = f'"{pythonw()}" "{SVR}" --port 443'
    # 1) machine-wide SYSTEM task, 2) per-user logon task, 3) Run key
    for args in (
        ["schtasks", "/Create", "/TN", TASK, "/TR", cmd, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"],
        ["schtasks", "/Create", "/TN", TASK, "/TR", cmd, "/SC", "ONLOGON", "/F"],
    ):
        if run(args).returncode == 0:
            print("  autostart : scheduled task (", "SYSTEM" if "/RU" in args else "logon", ")")
            return "task"
    r = run(["reg", "add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", RUNKEY, "/t", "REG_SZ", "/d", cmd, "/f"])
    print("  autostart : Run key" if r.returncode == 0 else "  autostart : FAILED")
    return "run"


def make_shortcut():
    ps = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$sc = $ws.CreateShortcut('{LNK}'); "
        f"$sc.TargetPath = '{pythonw()}'; "
        f"$sc.Arguments = '\"{LAUNCH}\"'; "
        f"$sc.WorkingDirectory = '{ROOT}'; "
        f"$sc.IconLocation = '{PARSEC},0'; "
        "$sc.Save()"
    )
    r = run(["powershell", "-NoProfile", "-Command", ps])
    print("  shortcut  :", "ok" if r.returncode == 0 else "FAILED")


def _is_reparse(path):
    attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
    return attrs != -1 and bool(attrs & 0x400)


def link_skill():
    """Junction ~/.agents/skills/<skill> -> <repo>/skills/<skill>, so skill://
    keeps working from any location (mklink /J needs no elevation)."""
    if not os.path.isdir(SKILL_SRC):
        return
    os.makedirs(os.path.dirname(SKILL_DST), exist_ok=True)
    if os.path.exists(SKILL_DST) and _is_reparse(SKILL_DST):
        os.rmdir(SKILL_DST)
    elif os.path.exists(SKILL_DST):
        print("  skill     : real directory exists, left alone")
        return
    r = run(["cmd", "/c", "mklink", "/J", SKILL_DST, SKILL_SRC])
    print("  skill     :", "linked" if r.returncode == 0 else "FAILED")


def start_server():
    if listening():
        print("  server    : already listening on :443")
        return
    subprocess.Popen([pythonw(), SVR, "--port", "443"], cwd=ROOT,
                     creationflags=0x00000008 | 0x00000200, close_fds=True)
    for _ in range(40):
        if listening():
            break
        time.sleep(0.25)
    print("  server    :", "started" if listening() else "FAILED to bind :443")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="127.0.0.1", help="IP of the machine running privsvr.py")
    ap.add_argument("--no-autostart", action="store_true")
    ap.add_argument("--no-session", action="store_true")
    ap.add_argument("--no-shortcut", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if os.name != "nt":
        sys.exit("windows only")
    if not is_admin():
        if args.dry_run:
            pass
        else:
            elevate(sys.argv[1:])
            sys.exit(0)

    print(f"install from: {ROOT}")
    local = args.server in ("127.0.0.1", "localhost")
    missing = [f for f in CERT_FILES if not os.path.exists(os.path.join(ROOT, f))]
    if args.dry_run:
        if missing:
            print(f"  certs     : would generate {', '.join(missing)}")
        else:
            print("  certs     : present")
        print(f"  CA        : would trust {CA}")
        print(f"  hosts     : would point {', '.join(DOMAINS)} -> {args.server}")
        print(f"  user.bin  : would create in {APPDATA}" if not args.no_session else "  user.bin  : skipped")
        cmd = f'"{pythonw()}" "{SVR}" --port 443'
        if local and not args.no_autostart:
            print(f"  autostart : would run {cmd}")
        print(f"  server    : would start {SVR}" if local else "  server    : remote, not started")
        if not args.no_shortcut:
            print(f"  shortcut  : would create {LNK}")
        print(f"  skill     : would link {SKILL_DST} -> {SKILL_SRC}")
        return
    if local:
        ensure_certs()
    elif not os.path.exists(CA):
        sys.exit(f"ca.pem missing in {ROOT}: copy it (or the whole folder) from the server machine")
    install_ca()
    write_hosts(args.server)
    if not args.no_session:
        write_session()
        enable_host()

    clear_autostart()
    if not args.no_autostart and local:
        install_autostart()
    elif not local:
        print("  autostart : skipped (remote server)")

    if local:
        start_server()
    if not args.no_shortcut:
        make_shortcut()
    link_skill()

    print("\nuninstall: python uninstall.py")


if __name__ == "__main__":
    main()
