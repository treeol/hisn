#!/usr/bin/env python3
"""Helpers for the leak suite (stdlib only).

  l8.py json-get FILE KEY            print a top-level JSON string value
  l8.py json-ok  FILE                exit 0 iff {"ok": true}
  l8.py json-has FILE KEY VALUE      exit 0 iff top-level KEY == VALUE
  l8.py ls-field ID FIELD < LS.json  print FIELD of session ID (hisn-ls/v2);
                                     empty if not listed / null
  l8.py ls-count ID FIELD < LS.json  print the length of the array FIELD of
                                     session ID (0 if absent/null/non-array)
  l8.py ls-client-fields ID < LS.json  print `label=L pid=N` of the first client
                                     of session ID, or `none`
  l8.py attach-ok < RESPONSE         exit 0 iff the first line is
                                     {"ok": true, "exec_id": "e-N", ...}
  l8.py audit-has FILE OP STAGE      exit 0 iff a grants.jsonl line has
                                     op == OP and stage == STAGE
  l8.py l8 INSPECT.json PLAN.json HOST_MOUNTINFO [GRANT_PATH:MODE ...]
                                     L8: sandbox mount table == plan, typed

L8 compares the sandbox's mount table (from `hisn inspect`) with the plan from
`hisn policy plan` (target, recursive, ro) plus "/" and the live grants:

  * every planned/granted mountpoint must exist in the sandbox, and a planned
    read-only mount must carry the `ro` option (a ro->rw regression fails);
  * a mountpoint in the sandbox that is neither planned nor granted is allowed
    ONLY if (a) it is one of the fixed /proc hardening mounts, or (b) it lies
    beneath a planned *recursive* bind AND the same path is a mountpoint in the
    host's mount table (a submount that the recursive bind imports) -- and such
    an imported submount must be read-only wherever the bind it sits under is
    read-only. Planned non-recursive mounts (tmpfs areas, /dev, non-recursive
    binds) import nothing, so an extra mount beneath them is a failure.
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


def load_json(path):
    with open(path) as f:
        return json.load(f)


def read_text(path):
    with open(path) as f:
        return f.read()


def mount_table(text):
    """mountpoint -> set of per-mount options (the 6th mountinfo field)."""
    rows = {}
    for line in text.splitlines():
        f = line.split(" ")
        if len(f) >= 7:
            rows[unescape(f[4])] = set(f[5].split(","))
    return rows


def l8(inspect_file, plan_file, host_mi_file, grants):
    ins = load_json(inspect_file)
    if ins.get("ok") is not True:
        print("inspect failed:", ins)
        return 1
    sandbox = mount_table(ins["mountinfo"])
    plan = {r["target"]: r for r in load_json(plan_file)}
    host = set(mount_table(read_text(host_mi_file)))
    live = {}
    for g in grants:
        path, _, mode = g.rpartition(":")
        live[path] = mode == "ro"
    problems = []

    expected = set(plan) | {"/"} | set(live)
    for m in sorted(expected - set(sandbox)):
        problems.append(f"missing from sandbox: {m}")
    for m, r in plan.items():
        if m in sandbox and r["ro"] is True and "ro" not in sandbox[m]:
            problems.append(f"planned read-only but mounted rw: {m}")
        if m in sandbox and r["ro"] is False and "ro" in sandbox[m]:
            problems.append(f"planned rw but mounted ro: {m}")
    for m, ro in live.items():
        if m in sandbox and ro and "ro" not in sandbox[m]:
            problems.append(f"ro grant mounted rw: {m}")
        if m in sandbox and not ro and "ro" in sandbox[m]:
            problems.append(f"rw grant mounted ro: {m}")

    recursive_roots = [m for m, r in plan.items() if r["recursive"]]
    for m in sorted(set(sandbox) - expected):
        if m in PROC_HARDENING:
            continue
        parents = [r for r in recursive_roots if under(m, r)]
        if parents and m in host:
            parent = max(parents, key=len)
            if plan[parent]["ro"] and "ro" not in sandbox[m]:
                problems.append(f"imported submount {m} is rw under read-only bind {parent}")
            continue
        problems.append(f"extra mount: {m}")

    if problems:
        print("L8 mismatch")
        for p in problems:
            print("  " + p)
        return 1
    print(f"L8 ok: {len(sandbox)} mounts, all accounted for, modes match")
    return 0


def find_session(doc, want):
    """The session WANT, matched by name or by id (the `--session` argument may
    be either). None if absent."""
    for s in doc.get("sessions", []):
        if want in (s.get("name"), s.get("id")):
            return s
    return None


def ls_field(doc_text, want, field):
    """FIELD of session WANT in an `ls --json` document ("" if absent)."""
    try:
        doc = json.loads(doc_text)
    except ValueError:
        return ""
    s = find_session(doc, want)
    if s is None:
        return ""
    v = s.get(field)
    return "" if v is None else str(v)


def ls_client_fields(doc_text, want):
    """`label=<label> pid=<pid>` of the first client of session WANT, or
    `none` when it has no client. Used by L74 to check that a client record
    carries its identity rather than an empty placeholder."""
    try:
        doc = json.loads(doc_text)
    except ValueError:
        return "none"
    s = find_session(doc, want)
    if s is None or not isinstance(s.get("clients"), list) or not s["clients"]:
        return "none"
    c = s["clients"][0]
    pid = c.get("pid")
    return "label=%s pid=%s" % (c.get("label", ""), "" if pid is None else pid)


def ls_count(doc_text, want, field):
    """Length of the array FIELD of session WANT (0 for absent/null/non-array).

    Used by L74 to compare `clients` with the live connection count (0 for a
    stopped session, whose `clients` is `[]`)."""
    try:
        doc = json.loads(doc_text)
    except ValueError:
        return 0
    s = find_session(doc, want)
    if s is not None:
        v = s.get(field)
        return len(v) if isinstance(v, list) else 0
    return 0


def attach_ok(resp_text):
    """True iff the first response line is ok:true with an e-N exec_id."""
    first = resp_text.split("\n", 1)[0]
    try:
        r = json.loads(first)
    except ValueError:
        return False
    eid = r.get("exec_id")
    return r.get("ok") is True and isinstance(eid, str) and eid.startswith("e-")


def audit_has(path, op, stage):
    """True iff an audit line in PATH has op == OP and stage == STAGE."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("op") == op and e.get("stage") == stage:
                    return True
    except OSError:
        return False
    return False


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "json-get":
        v = load_json(argv[2]).get(argv[3], "")
        print(v if isinstance(v, str) else json.dumps(v))
        return 0
    if cmd == "json-ok":
        return 0 if load_json(argv[2]).get("ok") is True else 1
    if cmd == "json-has":
        return 0 if str(load_json(argv[2]).get(argv[3])) == argv[4] else 1
    if cmd == "ls-field":
        print(ls_field(sys.stdin.read(), argv[2], argv[3]))
        return 0
    if cmd == "ls-count":
        print(ls_count(sys.stdin.read(), argv[2], argv[3]))
        return 0
    if cmd == "ls-client-fields":
        print(ls_client_fields(sys.stdin.read(), argv[2]))
        return 0
    if cmd == "attach-ok":
        return 0 if attach_ok(sys.stdin.read()) else 1
    if cmd == "audit-has":
        return 0 if audit_has(argv[2], argv[3], argv[4]) else 1
    if cmd == "l8":
        return l8(argv[2], argv[3], argv[4], argv[5:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
