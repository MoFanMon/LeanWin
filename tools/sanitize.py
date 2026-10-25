"""Rebuild with ASan/UBSan and check deterministic malformed PE inputs."""
import json
import datetime
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_pe import pe_fixture


def main():
    subprocess.run(["make"], cwd=ROOT, check=True)
    tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                           cwd=ROOT, capture_output=True, text=True, check=True)
    print(tests.stderr, end="")
    count = re.search(r"Ran (\d+) tests", tests.stderr)
    if not count:
        raise RuntimeError("cannot determine the completed test count")
    subprocess.run([sys.executable, "examples/build.py"], cwd=ROOT, check=True)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0", UBSAN_OPTIONS="halt_on_error=1")
    randomizer = random.Random(20261024)
    with tempfile.TemporaryDirectory(prefix="leanwin-sanitize-") as directory:
        folder = Path(directory)
        binary = folder / "leanwin-asan"
        subprocess.run([os.environ.get("CC", "cc"), "-D_POSIX_C_SOURCE=200809L", "-D_DARWIN_C_SOURCE",
                        "-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        str(ROOT / "src/main.c"), str(ROOT / "src/pe.c"), str(ROOT / "src/vm.c"),
                        "-o", str(binary)], check=True)
        path = folder / "mutated.exe"
        for i in range(120):
            data = pe_fixture(32 if i % 2 else 64, delayed=True)
            for _ in range(1 + i % 5):
                offset = randomizer.choice([0x3c, 0x84, 0x86, 0x94, 0x98, 0x98 + 56,
                    0x98 + 60, 0x98 + 108, 0x98 + 120, 0x98 + 240 + 16,
                    0x200, 0x20c, 0x300, 0x400]) + randomizer.randrange(4)
                if offset < len(data):
                    data[offset] = randomizer.randrange(256)
            if i % 9 == 0:
                data = data[:randomizer.randrange(len(data))]
            path.write_bytes(data)
            result = subprocess.run([str(binary), "inspect", str(path)], capture_output=True, env=env, timeout=3)
            if (result.returncode not in (0, 65) or b"AddressSanitizer" in result.stderr
                    or b"runtime error:" in result.stderr):
                raise RuntimeError((i, result.returncode, result.stderr.decode(errors="replace")))
            if result.returncode == 0:
                json.loads(result.stdout)
        for name, expected in [("hello32.exe", 37), ("hello64.exe", 37), ("files32.exe", 0), ("files64.exe", 0)]:
            result = subprocess.run([str(binary), "run", str(ROOT / "examples/bin" / name),
                        "--root", str(folder / "drive")], capture_output=True, env=env, timeout=3)
            if (result.returncode != expected or b"AddressSanitizer" in result.stderr
                    or b"runtime error:" in result.stderr):
                raise RuntimeError((name, result.returncode, result.stderr.decode(errors="replace")))
    report = {"generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "unit_tests": int(count.group(1)), "unit_test_status": "PASS",
              "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"],
              "deterministic_mutated_pe_inputs": 120, "sanitized_execution_examples": 4,
              "sanitizer_status": "PASS", "visible_gui_validation": "NOT AUTOMATED: compiled only",
              "native_windows_cross_validation": "NOT RUN"}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
