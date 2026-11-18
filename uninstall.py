#!/usr/bin/env python3
"""
Remove the Parsec LAN signaling setup from this machine.

  python uninstall.py                # full removal
  python uninstall.py --keep-hosts   # keep DNS redirect (e.g. moving the server)
  python uninstall.py --keep-cert    # keep the lab CA trusted

Keeps %APPDATA%\\Parsec\\user.bin and the Parsec patches untouched.
Needs an elevated shell.
"""
import argparse
import ctypes
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
CA = os.path.join(ROOT, "ca.pem")
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
MARK = "# parsec-lan"
TASK = "Parsec LAN Signaling"
RUNKEY = "ParsecLanSignaling"
LNK = os.path.join(os.environ["USERPROFILE"], "Desktop", "Parsec (LAN).lnk")
SKILL_SRC = os.path.join(ROOT, "skills", "parsec-lan-signaling")
SKILL_DST = os.path.join(os.environ["USERPROFILE"], ".agents", "skills", "parsec-lan-signaling")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


def elevate(argv):
    params = " ".join(f'"{a}"' for a in [os.path.abspath(__file__)] + argv)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, ROOT, 1)
    if rc <= 32:
        sys.exit("elevation failed (UAC declined)")


def stop_server():
    ps = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.CommandLine -like '*privsvr.py*' } | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
    )
    run(["powershell", "-NoProfile", "-Command", ps])
    print("  server    : stopped")


def remove_autostart():
    t = run(["schtasks", "/Delete", "/TN", TASK, "/F"])
    r = run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", RUNKEY, "/f"])
    print("  autostart : task", "removed" if t.returncode == 0 else "absent",
          "/ run key", "removed" if r.returncode == 0 else "absent")


def remove_hosts():
    with open(HOSTS, encoding="utf-8", errors="ignore") as f:
        lines = [ln.rstrip("\r\n") for ln in f]
    kept = [ln for ln in lines if MARK not in ln]
    with open(HOSTS, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(kept) + "\n")
    run(["ipconfig", "/flushdns"])
    print("  hosts     : redirect removed")


def remove_ca():
    r = run(["certutil", "-delstore", "Root", "Parsec Lab CA"])
    print("  CA        :", "removed" if r.returncode == 0 else "absent")


def remove_shortcut():
    if os.path.exists(LNK):
        os.remove(LNK)
        print("  shortcut  : removed")
    else:
        print("  shortcut  : absent")


def _is_reparse(path):
    attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
    return attrs != -1 and bool(attrs & 0x400)


def unlink_skill():
    """Remove the junction only when it points into this repo."""
    if not _is_reparse(SKILL_DST):
        print("  skill     : absent")
        return
    try:
        target = os.path.realpath(SKILL_DST)
        if os.path.commonpath([target, os.path.realpath(ROOT)]) != os.path.realpath(ROOT):
            print("  skill     : points elsewhere, left alone")
            return
        os.rmdir(SKILL_DST)
        print("  skill     : unlinked")
    except Exception as e:
        print("  skill     : skipped", e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-hosts", action="store_true")
    ap.add_argument("--keep-cert", action="store_true")
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

    print(f"uninstall: {ROOT}")
    if args.dry_run:
        print(f"  server    : would stop processes running privsvr.py")
        print(f"  autostart : would remove task '{TASK}' and Run value '{RUNKEY}'")
        if not args.keep_hosts:
            print(f"  hosts     : would drop lines marked '{MARK}'")
        if not args.keep_cert:
            print(f"  CA        : would remove 'Parsec Lab CA' from Root")
        print(f"  shortcut  : would remove {LNK}")
        print(f"  skill     : would unlink {SKILL_DST}")
        return
    stop_server()
    remove_autostart()
    if not args.keep_hosts:
        remove_hosts()
    if not args.keep_cert and os.path.exists(CA):
        remove_ca()
    remove_shortcut()
    unlink_skill()
    print("\nkept: user.bin, config.json, patched parsecd files")


if __name__ == "__main__":
    main()
