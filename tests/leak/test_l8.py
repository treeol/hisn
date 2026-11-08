#!/usr/bin/env python3
"""Self-test of the L8 comparator on synthetic mount tables (no sandbox needed).

It proves the comparator rejects what it claims to reject; it says nothing
about a real hisn session. Run: python3 tests/leak/test_l8.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("l8", os.path.join(HERE, "l8.py"))
l8 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(l8)

PLAN = [
    {"target": "/usr", "recursive": True, "ro": True},
    {"target": "/etc", "recursive": False, "ro": True},
    {"target": "/tmp", "recursive": False, "ro": False},
    {"target": "/work/p", "recursive": True, "ro": False},
    {"target": "/proc", "recursive": False, "ro": None},
]


def mi(rows):
    return "\n".join(
        f"{i} 1 0:{i} / {p} {opts} - tmpfs x rw" for i, (p, opts) in enumerate(rows, 10)
    )


GOOD = [("/", "rw"), ("/usr", "ro,nosuid"), ("/etc", "ro"), ("/tmp", "rw"), ("/work/p", "rw,nosuid"), ("/proc", "rw")]
HOST = [("/", "rw"), ("/usr", "ro"), ("/usr/share/x", "ro"), ("/work/p/sub", "rw"), ("/tmp/private-data", "rw")]


def run(sandbox_rows, grants=(), host_rows=HOST, plan=PLAN):
    with tempfile.TemporaryDirectory() as d:
        ins, pl, hm = (os.path.join(d, n) for n in ("i", "p", "h"))
        json.dump({"ok": True, "mountinfo": mi(sandbox_rows)}, open(ins, "w"))
        json.dump(plan, open(pl, "w"))
        open(hm, "w").write(mi(host_rows))
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = l8.l8(ins, pl, hm, list(grants))
        return rc, buf.getvalue()


class L8(unittest.TestCase):
    def test_exact_table_passes(self):
        self.assertEqual(run(GOOD)[0], 0)

    def test_missing_mount_fails(self):
        rc, out = run([r for r in GOOD if r[0] != "/etc"])
        self.assertEqual(rc, 1)
        self.assertIn("missing from sandbox: /etc", out)

    def test_extra_mount_fails(self):
        rc, out = run(GOOD + [("/srv/leak", "rw")])
        self.assertEqual(rc, 1)
        self.assertIn("extra mount: /srv/leak", out)

    def test_reviewer_case_host_submount_under_private_tmpfs_fails(self):
        # /tmp is a non-recursive tmpfs: it must NOT import /tmp/private-data
        rc, out = run(GOOD + [("/tmp/private-data", "rw")])
        self.assertEqual(rc, 1, out)
        self.assertIn("extra mount: /tmp/private-data", out)

    def test_imported_submount_under_recursive_bind_is_allowed(self):
        self.assertEqual(run(GOOD + [("/usr/share/x", "ro")])[0], 0)

    def test_imported_submount_under_recursive_bind_must_be_ro_when_parent_is(self):
        rc, out = run(GOOD + [("/usr/share/x", "rw")])
        self.assertEqual(rc, 1)
        self.assertIn("rw under read-only bind /usr", out)

    def test_submount_not_present_on_host_is_not_imported(self):
        rc, _ = run(GOOD + [("/usr/invented", "ro")])
        self.assertEqual(rc, 1)

    def test_ro_to_rw_regression_fails(self):
        rows = [("/usr", "rw") if r[0] == "/usr" else r for r in GOOD]
        rc, out = run(rows)
        self.assertEqual(rc, 1)
        self.assertIn("planned read-only but mounted rw: /usr", out)

    def test_rw_to_ro_regression_fails(self):
        rows = [("/tmp", "ro") if r[0] == "/tmp" else r for r in GOOD]
        self.assertEqual(run(rows)[0], 1)

    def test_grants_must_exist_and_have_the_right_mode(self):
        self.assertEqual(run(GOOD + [("/g/ro", "ro")], ["/g/ro:ro"])[0], 0)
        self.assertEqual(run(GOOD, ["/g/ro:ro"])[0], 1, "grant missing")
        rc, out = run(GOOD + [("/g/ro", "rw")], ["/g/ro:ro"])
        self.assertEqual(rc, 1)
        self.assertIn("ro grant mounted rw", out)
        rc, out = run(GOOD + [("/g/rw", "ro")], ["/g/rw:rw"])
        self.assertEqual(rc, 1)
        self.assertIn("rw grant mounted ro", out)
        # an un-granted extra mount is still rejected when other grants exist
        self.assertEqual(run(GOOD + [("/g/ro", "ro"), ("/g/other", "ro")], ["/g/ro:ro"])[0], 1)

    def test_proc_hardening_mounts_are_allowed_but_only_those(self):
        self.assertEqual(run(GOOD + [("/proc/kcore", "ro"), ("/proc/sys", "ro")])[0], 0)
        self.assertEqual(run(GOOD + [("/proc/other", "ro")])[0], 1)

    def test_failed_inspect_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "i")
            json.dump({"ok": False}, open(p, "w"))
            self.assertEqual(l8.l8(p, p, p, []), 1)


class HarnessHelpers(unittest.TestCase):
    """0.4.0 L52/L61: JSON-parsed checks instead of greps."""

    LS = json.dumps({"schema": "hisn-ls/v2", "sessions": [
        {"id": "l61-42", "state": "stopped", "dir": "/tmp/hisn-1000/l61-42",
         "clients": [], "execs": []},
        {"id": "l61-4", "state": "running", "dir": None,
         "clients": [{"uid": 1000, "label": "local"}],
         "execs": [{"exec_id": "e-1", "attach": True}]},
    ]})

    def test_ls_field_matches_the_exact_id(self):
        self.assertEqual(l8.ls_field(self.LS, "l61-42", "state"), "stopped")
        self.assertEqual(l8.ls_field(self.LS, "l61-4", "state"), "running")
        self.assertEqual(l8.ls_field(self.LS, "l61-42", "dir"), "/tmp/hisn-1000/l61-42")
        self.assertEqual(l8.ls_field(self.LS, "l61-4", "dir"), "")
        self.assertEqual(l8.ls_field(self.LS, "l61-$$", "state"), "")
        self.assertEqual(l8.ls_field("not json", "l61-42", "state"), "")

    def test_ls_count_reads_array_lengths(self):
        # 0.4.1 step 3/4: `clients` is [] for a stopped session, a live count
        # for a running one; a missing/non-array field reads 0.
        self.assertEqual(l8.ls_count(self.LS, "l61-42", "clients"), 0)
        self.assertEqual(l8.ls_count(self.LS, "l61-4", "clients"), 1)
        self.assertEqual(l8.ls_count(self.LS, "l61-4", "execs"), 1)
        self.assertEqual(l8.ls_count(self.LS, "l61-4", "state"), 0)
        self.assertEqual(l8.ls_count(self.LS, "nope", "clients"), 0)
        self.assertEqual(l8.ls_count("not json", "l61-4", "clients"), 0)

    def test_attach_ok_needs_ok_true_and_an_exec_id(self):
        self.assertTrue(l8.attach_ok('{"exec_id":"e-1","ok":true,"pid":3}\n{"exit":{}}'))
        self.assertFalse(l8.attach_ok('{"ok":true,"pid":3}'))
        self.assertFalse(l8.attach_ok('{"exec_id":"e-1","ok":false}'))
        self.assertFalse(l8.attach_ok('{"error":"E_BAD_REQUEST","ok":false}'))
        self.assertFalse(l8.attach_ok("ERR:timed out"))

    def test_audit_has_parses_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "grants.jsonl")
            with open(p, "w") as f:
                f.write('{"op":"attach","stage":"request","path":"/bin/sh"}\n')
                f.write("\n")
                f.write('{"op":"lease","stage":"expired","result":"idle"}\n')
            self.assertTrue(l8.audit_has(p, "attach", "request"))
            self.assertTrue(l8.audit_has(p, "lease", "expired"))
            self.assertFalse(l8.audit_has(p, "lease", "request"))
            self.assertFalse(l8.audit_has(os.path.join(d, "missing"), "lease", "expired"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
