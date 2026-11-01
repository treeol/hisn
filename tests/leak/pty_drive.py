#!/usr/bin/env python3
"""L20 driver: run `hisn exec --tty` on a real pty and change its size.

usage: pty_drive.py HISN SESSION PROBE

The child's controlling terminal is a pty we own, set to 80x24 before `hisn
exec` starts. The probe (`leakprobe tty-resize`) prints `FIRST isatty=<0|1>
size=<cols>x<rows>`, waits for SIGWINCH and prints `RESIZED size=...`. We
resize our pty to 100x30 after the first line: the kernel signals `hisn exec`
(the foreground process of our pty), which must propagate the new size to the
sandbox pty so that the probe sees SIGWINCH and the new size.

Prints `RESULT first=<...> resized=<...>` and exits 0 when both are as
expected, 1 otherwise. Needs only python3 (no `script`).
"""
import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time


def winsz(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def main(argv):
    hisn, session, probe = argv[1:4]
    pid, master = pty.fork()
    if pid == 0:
        winsz(0, 24, 80)
        os.execv(hisn, [hisn, "exec", "--session", session, "--tty", "--", probe, "tty-resize"])
    buf = b""
    resized_sent = False
    deadline = time.time() + 20
    while time.time() < deadline:
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        text = buf.decode("utf-8", "replace")
        if not resized_sent and "FIRST" in text and "\n" in text[text.index("FIRST"):]:
            winsz(master, 30, 100)
            resized_sent = True
        if "RESIZED" in text or "NO_WINCH" in text:
            break
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    lines = [l.strip() for l in buf.decode("utf-8", "replace").replace("\r", "").split("\n")]
    first = next((l for l in lines if l.startswith("FIRST")), "")
    resized = next((l for l in lines if l.startswith("RESIZED") or l.startswith("NO_WINCH")), "")
    print(f"RESULT first=[{first}] resized=[{resized}]")
    ok = first == "FIRST isatty=1 size=80x24" and resized == "RESIZED size=100x30"
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
