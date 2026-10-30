"""Run the same small PE programs through LeanWin or native Windows."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
sys.path.insert(0, str(ROOT / "tests"))
from build import console, files
from test_tls import TLSProgram
from test_nls import nls_probe, NLS_PROBE_EXPECTED
from kernel_fixture import Probe, heap_probe, virtual_probe
from test_resources import resource_probe
from test_threads import thread_probe, event_probe, thread_tls_probe
from test_process import process_probe, context_probe
from test_simd import simd_probe, aligned_simd_probe
from test_version import condition_probe, version_probe
from test_locale import locale_probe, locale_thread_probe, locale_info_probe, ordinal_probe, system_info_probe
from test_fpu import fpu_control_probe, fpu_thread_probe, fpu_environment_probe
from test_classes import common_classes_probe, class_lifecycle_probe
from test_cpu_startup import byte_immediate_probe, repeat_return_probe, scan_probe, not_probe


def tls_probe(bits):
    p = TLSProgram(bits, [("KERNEL32.dll", "ExitProcess")])
    p.prologue()
    p.tls_pointer()
    p.require_equal(b"\x81\x38\x5d\0\0\0")
    p.require_equal(b"\x81\x78\x04\0\0\0\0")
    p.exit(0)
    entry_failure = len(p.code)
    p.exit(99)
    for offset in p.failures:
        struct.pack_into("<i", p.code, offset, entry_failure - offset - 4)
    p.failures = []
    p.callback()
    if bits == 64:
        p.mov(0, p.base)
        p.require_equal(b"\x48\x39\xc1")
        p.require_equal(b"\x83\xfa\x01")
        p.require_equal(b"\x49\x83\xf8\0")
        p.emit(b"\x48\x89\xe0\x83\xe0\x0f")
        p.require_equal(b"\x83\xf8\x08")
    else:
        for offset, expected in ((4, p.base), (8, 1), (12, 0)):
            p.require_equal(b"\x81\x7c\x24" + bytes([offset]) + struct.pack("<I", expected))
    p.tls_pointer()
    p.require_equal(b"\x81\x38\x11\x22\x33\x44")
    p.emit(b"\xc7\x00\x5d\0\0\0")
    p.callback_return()
    callback_failure = len(p.code)
    p.prologue()
    p.exit(99)
    for offset in p.failures:
        struct.pack_into("<i", p.code, offset, callback_failure - offset - 4)
    return p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, help="LeanWin binary; omit to execute natively on Windows")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.runner and sys.platform != "win32":
        parser.error("native PE execution requires Windows; on macOS/Linux pass --runner ./build/leanwin")
    runner = args.runner.resolve() if args.runner else None
    report = {"backend": "leanwin" if runner else "native-windows", "cases": []}
    with tempfile.TemporaryDirectory(prefix="leanwin-smoke-") as directory:
        for bits in (32, 64):
            cases = [("console", console(bits), 37, b"Hello from a Windows EXE on macOS!\r\n"),
                     ("files", files(bits=bits), 0, b"LeanWin file round trip.\n"),
                     ("tls", tls_probe(bits), 0, b""),
                     ("nls", nls_probe(bits), 0, NLS_PROBE_EXPECTED),
                     ("heap", heap_probe(bits), 0, b""),
                     ("virtual", virtual_probe(bits), 0, b""),
                     ("resources", resource_probe(bits, False), 0, b""),
                     ("named-resources", resource_probe(bits, True), 0, b""),
                     ("thread", thread_probe(bits), 0, b""),
                     ("event", event_probe(bits), 0, b""),
                     ("thread-tls", thread_tls_probe(bits), 0, b""),
                     ("process", process_probe(bits), 0, b""),
                     ("context", context_probe(bits), 0, b""),
                     ("simd", simd_probe(bits), 0, b""),
                     ("aligned-simd", aligned_simd_probe(bits), 0, b""),
                     ("version-condition", condition_probe(bits), 0, b"\x18\0\x20\0\0\0\0\x80"),
                     ("version-query", version_probe(bits), 0, b""),
                     ("locale", locale_probe(bits), 0, b""),
                     ("thread-locale", locale_thread_probe(bits), 0, b""),
                     ("locale-info", locale_info_probe(bits), 0, b""),
                     ("ordinal", ordinal_probe(bits), 0, b""),
                     ("system-info", system_info_probe(bits), 0, b""),
                     ("x87-control", fpu_control_probe(bits), 0, b""),
                     ("x87-thread", fpu_thread_probe(bits), 0, b""),
                     ("x87-env", fpu_environment_probe(bits), 0, b""),
                     ("x87-env16", fpu_environment_probe(bits,True), 0, b""),
                     ("common-classes", common_classes_probe(bits), 0, b""),
                     ("common-classes-ex", common_classes_probe(bits,True), 0, b""),
                     ("class-lifecycle", class_lifecycle_probe(bits,False), 0, b""),
                     ("class-lifecycle-ex", class_lifecycle_probe(bits), 0, b""),
                     ("byte-immediate", byte_immediate_probe(bits), 0, b""),
                     ("rep-ret", repeat_return_probe(bits), 0, b""),
                     ("scan", scan_probe(bits), 0, b""),
                     ("not", not_probe(bits), 0, b"")]
            for name, program, expected_exit, expected_stdout in cases:
                folder = Path(directory) / f"{name}{bits}"
                folder.mkdir()
                executable = folder / "test.exe"
                executable.write_bytes(program.image())
                if name == "process":
                    child = Probe([], bits); child.exit(37)
                    (folder / "child.exe").write_bytes(child.image())
                command = [str(runner), "run", str(executable), "--root", str(folder)] if runner else [str(executable)]
                result = subprocess.run(command, cwd=folder, capture_output=True, timeout=10)
                if result.returncode != expected_exit or result.stdout != expected_stdout:
                    raise RuntimeError((name, bits, result.returncode, result.stdout, result.stderr))
                if name == "files" and (folder / "example.txt").read_bytes() != b"LeanWin file round trip.\n":
                    raise RuntimeError("file round trip did not preserve the payload")
                report["cases"].append({"name": f"{name}{bits}", "status": "PASS", "exit_code": result.returncode})
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
