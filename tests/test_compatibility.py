import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_pe import pe_fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
from build import console


class CompatibilityTests(unittest.TestCase):
    def check_image(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "program.exe"
            path.write_bytes(data)
            return subprocess.run([sys.executable, str(ROOT / "tools/compatibility.py"), str(path)],
                                  env=os.environ, capture_output=True, text=True, timeout=5)

    def test_all_missing_imports_are_reported_including_ordinals(self):
        result = self.check_image(pe_fixture(delayed=True))
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["static_import_entries"], 3)
        self.assertEqual(report["supported_import_entries"], 2)
        self.assertEqual(report["missing_import_entries"], 1)
        self.assertEqual(report["missing_imports"], [{"dll": "KERNEL32.dll", "symbol": "#7", "delayed": False}])
        self.assertFalse(report["execution_validated"])

    def test_supported_import_names_do_not_claim_successful_execution(self):
        result = self.check_image(console().image())
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["supported_import_entries"], 3)
        self.assertEqual(report["missing_imports"], [])
        self.assertFalse(report["execution_validated"])

    def test_invalid_pe_does_not_produce_a_compatibility_report(self):
        result = self.check_image(b"not a PE image")
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
