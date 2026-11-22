#!/usr/bin/env python3
"""Wire capture for the 0.6.4 B3 compatibility check.

Usage: compat_wire.py HISN_BIN

For every existing command (none of the 0.6.4 options), run the CLI binary
against a FAKE supervisor (a unix socket in a throw-away runtime dir, session
record at protocol revision 3) and print, as one JSON object on stdout, the
request line the CLI sent for each case. The fake never starts a sandbox, so
this is safe on any host. Run it for a v0.6.3 build and for HEAD: the two
outputs must be equal (tests/leak/compat_063.sh does that, and compares the
v0.6.3 output with tests/fixtures/v063-wire.json).
"""
import array
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

SESSION = "compat1"
TOKEN = "tok-compat-0123456789"

# case name -> (argv after the binary, extra env)
CASES = {
    "exec": (["exec", "--no-tty", "--session", SESSION, "--", "echo", "hi"], {}),
    "exec_env_cwd_client": (
        ["exec", "--no-tty", "--session", SESSION, "--cwd", "/w", "--env", "A=1",
         "--env", "B=two", "--client", "lbl", "--", "sh", "-c", "x y"], {}),
    "exec_seat_token": (
        ["exec", "--no-tty", "--session", SESSION, "--", "id"], {"HISN_SEAT_TOKEN": TOKEN}),
    "grant": (["grant", "--session", SESSION, "/a/b"], {}),
    "grant_rw_recursive": (["grant", "--session", SESSION, "--rw", "--recursive", "/a/b"], {}),
    "grant_seat_token": (["grant", "--session", SESSION, "/a/b"], {"HISN_SEAT_TOKEN": TOKEN}),
    "revoke": (["revoke", "--session", SESSION, "/a/b"], {}),
    "revoke_hard_kill_holders": (
        ["revoke", "--session", SESSION, "--hard", "--kill-holders", "/a/b"], {}),
    "kill": (["kill", "--session", SESSION], {}),
    "kill_int": (["kill", "--session", SESSION, "--signal", "INT"], {}),
    "kill_seat_token": (["kill", "--session", SESSION], {"HISN_SEAT_TOKEN": TOKEN}),
    "inspect": (["inspect", "--session", SESSION], {}),
    "ls_session": (["ls", "--session", SESSION, "--json"], {}),
    "ls_session_seat_token": (["ls", "--session", SESSION, "--json"], {"HISN_SEAT_TOKEN": TOKEN}),
    "ls_all": (["ls", "--json"], {}),
    "note": (["note", "--session", SESSION, "hello world"], {}),
    "note_marker": (["note", "--session", SESSION, "--marker", "m1"], {}),
    "note_seat_token": (["note", "--session", SESSION, "hello"], {"HISN_SEAT_TOKEN": TOKEN}),
}


def serve(sock, got):
    def handle(conn):
        try:
            buf = b""
            while b"\n" not in buf:
                msg, anc, _flags, _addr = conn.recvmsg(65536, socket.CMSG_LEN(16 * 4))
                for level, typ, data in anc:
                    if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                        fds = array.array("i")
                        fds.frombytes(data[: len(data) - len(data) % fds.itemsize])
                        for fd in fds:
                            os.close(fd)
                if not msg:
                    return
                buf += msg
            line = buf.split(b"\n", 1)[0].decode()
            got.append(line)
            req = json.loads(line)
            if req.get("op") == "exec":
                conn.sendall(b'{"ok":true,"pid":5,"exec_id":"e-0"}\n{"exit":{"code":0}}\n')
            else:
                conn.sendall(b'{"ok":true,"grants":[],"sessions":[],"execs":[]}\n')
        except Exception:
            pass
        finally:
            conn.close()

    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def run_case(binary, argv, extra_env):
    root = tempfile.mkdtemp(prefix="hisn-compat-")
    try:
        rt = os.path.join(root, "run")
        sdir = os.path.join(rt, "hisn", SESSION)
        os.makedirs(sdir, mode=0o700)
        for d in (rt, os.path.join(rt, "hisn"), sdir):
            os.chmod(d, 0o700)
        with open(os.path.join(sdir, "session.json"), "w") as f:
            json.dump({
                "schema": "hisn-session/v1", "id": SESSION, "name": None,
                "owner": {"uid": os.getuid(), "label": "local", "client_id": "c1"},
                "created": {"ts": "2026-11-22T00:00:00Z", "by": "local"},
                "cwd": "/w", "rootfs": None, "network": "none", "state": "running",
                "hisn_version": "0.6.3", "protocol_revision": 3,
            }, f)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(os.path.join(sdir, "control.sock"))
        sock.listen(8)
        got = []
        threading.Thread(target=serve, args=(sock, got), daemon=True).start()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.path.join(root, "home"),
            "XDG_RUNTIME_DIR": rt,
            "XDG_STATE_HOME": os.path.join(root, "state"),
        }
        os.makedirs(env["HOME"])
        env.update(extra_env)
        try:
            subprocess.run([binary] + argv, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        except subprocess.TimeoutExpired:
            pass
        sock.close()
        return got
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    binary = os.path.realpath(sys.argv[1])
    out = {}
    for name, (argv, env) in CASES.items():
        got = run_case(binary, argv, env)
        # `ls --json` also sends `sessioninfo` per live session: keep every
        # line, in order, so a changed or extra request is a difference too.
        out[name] = got
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
