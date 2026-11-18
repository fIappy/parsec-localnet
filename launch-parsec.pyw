"""
Start the LAN signaling server (if this folder has one and :443 is free),
wait for it, then launch Parsec. Path is derived from this file, so the
folder can be moved freely.

pythonw.exe launch-parsec.pyw
"""
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
SVR = os.path.join(ROOT, "privsvr.py")
PARSEC = os.environ.get("PARSEC_EXE", r"C:\Program Files\Parsec\parsecd.exe")
DETACHED = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP


def listening(port=443):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def pythonw():
    exe = sys.executable
    cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return cand if os.path.exists(cand) else exe


def main():
    if os.path.exists(SVR) and not listening():
        subprocess.Popen([pythonw(), SVR, "--port", "443"],
                         cwd=ROOT, creationflags=DETACHED, close_fds=True)
        for _ in range(40):
            if listening():
                break
            time.sleep(0.25)

    subprocess.Popen([PARSEC], close_fds=True)


if __name__ == "__main__":
    main()
