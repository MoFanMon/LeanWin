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
from test_tls import TLSProgram, DATA


def main():
    subprocess.run(["make"], cwd=ROOT, check=True)
    tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                           cwd=ROOT, capture_output=True, text=True, check=True)
    print(tests.stderr, end="")
    count = re.search(r"Ran (\d+) tests", tests.stderr)
    if not count:
        raise RuntimeError("cannot determine the completed test count")
    subprocess.run([sys.executable, "examples/build.py"], cwd=ROOT, check=True)
    randomizer = random.Random(20261024)
    with tempfile.TemporaryDirectory(prefix="leanwin-sanitize-") as directory:
        folder = Path(directory)
        binary = folder / "leanwin-asan"
        subprocess.run([os.environ.get("CC", "cc"), "-D_POSIX_C_SOURCE=200809L", "-D_DARWIN_C_SOURCE",
                        "-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        str(ROOT / "src/main.c"), str(ROOT / "src/pe.c"), str(ROOT / "src/vm.c"),
                        "-o", str(binary)], check=True)
        env = dict(os.environ, LEANWIN_CLI=str(binary),
                   ASAN_OPTIONS=f"detect_leaks=0:halt_on_error=1:log_path={folder}/sanitizer",
                   UBSAN_OPTIONS=f"halt_on_error=1:log_path={folder}/sanitizer")
        sanitized_tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                           cwd=ROOT, capture_output=True, text=True, env=env, check=True)
        print(sanitized_tests.stderr, end="")
        sanitized_count = re.search(r"Ran (\d+) tests", sanitized_tests.stderr)
        if not sanitized_count or sanitized_count.group(1) != count.group(1):
            raise RuntimeError("sanitized suite did not run the same tests as the normal suite")
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
        for i in range(120):
            p = TLSProgram(32 if i % 2 else 64)
            p.finish()
            p.callback()
            p.callback_return()
            data = p.image()
            header = 0x98 + (96 if p.bits == 32 else 112) + 9 * 8
            tls = 0x600 + p.tls - DATA
            callback_table = 0x600 + p.callback_table - DATA
            for _ in range(1 + i % 5):
                offset = randomizer.choice([header, header + 4, tls + randomizer.randrange(p.word * 4 + 8),
                                           callback_table + randomizer.randrange(p.word * 3)])
                data[offset] = randomizer.randrange(256)
            path.write_bytes(data)
            result = subprocess.run([str(binary), "run", str(path), "--root", str(folder / "drive"),
                         "--max-steps", "1000"], capture_output=True, env=env, timeout=3)
            if result.returncode < 0 or b"AddressSanitizer" in result.stderr or b"runtime error:" in result.stderr:
                raise RuntimeError(("TLS", i, result.returncode, result.stderr.decode(errors="replace")))
        # Negative-path tests capture stderr and may intentionally accept nonzero
        # exits. Sanitizer logs still make any instrumented process failure fatal.
        logs = [p for p in folder.glob("sanitizer.*") if p.stat().st_size]
        if logs:
            raise RuntimeError("sanitizer reported an error:\n" + logs[0].read_text())
    report = {"generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "unit_tests": int(count.group(1)), "unit_test_status": "PASS",
              "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"],
              "sanitized_unit_tests": int(sanitized_count.group(1)),
              "deterministic_mutated_pe_inputs": 120, "sanitized_execution_examples": 4,
              "deterministic_mutated_tls_execution_inputs": 120,
              "sanitizer_status": "PASS", "visible_gui_validation": "NOT AUTOMATED: compiled only",
              "native_windows_cross_validation": "NOT RUN"}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
