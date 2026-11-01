#!/usr/bin/env python3
"""Helpers for the leak suite (stdlib only).

  l8.py json-get FILE KEY            print a top-level JSON string value
  l8.py json-ok  FILE                exit 0 iff {"ok": true}
  l8.py json-has FILE KEY VALUE      exit 0 iff top-level KEY == VALUE
  l8.py l8 INSPECT.json PLAN.json HOST_MOUNTINFO [GRANT_PATH ...]
                                     L8: sandbox mount table == plan (see below)

L8 compares the sandbox's mountpoints (from `hisn inspect`) with the set
derived from the policy by `hisn policy plan`, plus "/" (the root tmpfs) and
the paths of live grants. Two documented, bounded exceptions:
  * submounts of /proc created by procfs hardening (fixed name list);
  * mounts that a *recursive* bind imports because they exist at the same path
    in the host mount table (e.g. a separate filesystem below /usr).
Anything else is reported as an extra mount, and any planned mount that is
missing is reported too.
"""
import json
import sys

PROC_HARDENING = {
    "/proc/" + n
    for n in (
        "kcore", "keys", "latency_stats", "timer_list", "timer_stats",
        "sched_debug", "acpi", "scsi", "bus", "fs", "irq", "sys", "sysrq-trigger",
    )
}


def unescape(s):
    out, i = bytearray(), 0
    b = s.encode()
    while i < len(b):
        if b[i] == 0x5C and i + 3 < len(b) and all(0x30 <= c <= 0x37 for c in b[i + 1:i + 4]):
            out.append(int(b[i + 1:i + 4], 8))
            i += 4
        else:
            out.append(b[i])
            i += 1
    return out.decode(errors="replace")


def mountpoints(text):
    pts = []
    for line in text.splitlines():
        f = line.split(" ")
        if len(f) >= 7:
            pts.append(unescape(f[4]))
    return pts


def under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def l8(inspect_file, plan_file, host_mi_file, grants):
    ins = json.load(open(inspect_file))
    if ins.get("ok") is not True:
        print("inspect failed:", ins)
        return 1
    sandbox = set(mountpoints(ins["mountinfo"]))
    plan = set(json.load(open(plan_file)))
    host = set(mountpoints(open(host_mi_file).read()))
    expected = plan | {"/"} | set(grants)
    recursive_roots = [p for p in plan if p.startswith(("/usr", "/bin", "/sbin", "/lib", "/opt", "/nix"))
                       and p.count("/") == 1]
    missing = sorted(expected - sandbox)
    extra = []
    for m in sorted(sandbox - expected):
        if m in PROC_HARDENING:
            continue
        if m in host and any(under(m, r) for r in recursive_roots + sorted(plan)):
            continue
        extra.append(m)
    if missing or extra:
        print("L8 mismatch")
        print("  missing from sandbox:", missing)
        print("  extra in sandbox:   ", extra)
        return 1
    print(f"L8 ok: {len(sandbox)} mounts, all accounted for")
    return 0


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "json-get":
        v = json.load(open(argv[2])).get(argv[3], "")
        print(v if isinstance(v, str) else json.dumps(v))
        return 0
    if cmd == "json-ok":
        return 0 if json.load(open(argv[2])).get("ok") is True else 1
    if cmd == "json-has":
        return 0 if str(json.load(open(argv[2])).get(argv[3])) == argv[4] else 1
    if cmd == "l8":
        return l8(argv[2], argv[3], argv[4], argv[5:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
