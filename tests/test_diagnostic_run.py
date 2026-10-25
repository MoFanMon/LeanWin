import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from kernel_fixture import Probe

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


class DiagnosticRunTests(unittest.TestCase):
    def test_unused_missing_import_can_be_deferred_without_faking_a_call(self):
        p = Probe(["LeanWinMissingFunction"])
        p.exit(23)
        with tempfile.TemporaryDirectory() as folder:
            exe, report = Path(folder)/"program.exe", Path(folder)/"report.json"
            exe.write_bytes(p.image())
            base = [str(CLI), "run", str(exe), "--root", str(Path(folder)/"drive")]
            strict = subprocess.run(base, capture_output=True)
            self.assertEqual(strict.returncode, 65)
            result = subprocess.run([*base, "--defer-imports", "--report", str(report)], capture_output=True)
            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertGreater(json.loads(report.read_text())["instructions"], 0)

    def test_calling_a_deferred_import_fails_and_preserves_execution_report(self):
        p = Probe(["LeanWinMissingFunction"])
        p.call("LeanWinMissingFunction")
        p.exit(0)
        with tempfile.TemporaryDirectory() as folder:
            exe, report = Path(folder)/"program.exe", Path(folder)/"report.json"
            exe.write_bytes(p.image())
            result = subprocess.run([str(CLI), "run", str(exe), "--root", str(Path(folder)/"drive"),
                                     "--defer-imports", "--report", str(report)], capture_output=True)
            self.assertEqual(result.returncode, 65)
            self.assertIn(b"KERNEL32.dll!LeanWinMissingFunction", result.stderr)
            data = json.loads(report.read_text())
            self.assertEqual(data["status"], "error")
            self.assertGreater(data["instructions"], 0)
            self.assertIn("LeanWinMissingFunction", data["error"])


if __name__ == "__main__":
    unittest.main()
