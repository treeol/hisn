"""Journal harness regression: no hisn invocation or session is started."""
import pathlib
import subprocess
import tempfile
import unittest


class JournalHarnessTests(unittest.TestCase):
    def test_l88_uses_normal_completion_not_stop(self):
        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "tests/leak/run.sh").read_text()
        case = source.split("# ================================================ L88:", 1)[1]
        case = case.split("# Every id in MANIFEST", 1)[0]
        start = next(line for line in case.splitlines()
                     if "if start_session" in line)
        self.assertNotIn("--detach", start,
                         "L88 must complete its probe normally, removing the dir")
        self.assertIn('end_session "$L88_CWD" "$L88_PID"', case)

    def test_binary_path_survives_changing_directory(self):
        repo = pathlib.Path(__file__).resolve().parents[2]
        setup = next(line for line in (repo / "tests/leak/run.sh").read_text().splitlines()
                     if line.startswith("HISN="))
        with tempfile.TemporaryDirectory(dir=repo / "target") as tmp:
            root = pathlib.Path(tmp)
            (root / "other").mkdir()
            probe = root / "probe"
            probe.write_text('#!/bin/sh\nprintf "L88-NOTE-TEXT\\n"\n')
            probe.chmod(0o700)
            script = setup + '\ncd other\n"$HISN"\n'
            result = subprocess.run(["bash", "-c", script, "path-test", "./probe"],
                                    cwd=root, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "L88-NOTE-TEXT\n")


if __name__ == "__main__":
    unittest.main()
