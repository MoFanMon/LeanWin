import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from kernel_fixture import Probe, reg

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


def process_probe(bits=64, name="child.exe", expected=37):
    p = Probe(["CreateProcessW", "WaitForSingleObject", "GetExitCodeProcess", "CloseHandle"], bits)
    executable = p.wide(name)
    startup = p.blob(struct.pack("<I", 104 if bits == 64 else 68) + b"\0" * (100 if bits == 64 else 64))
    info, code = p.blob(b"\0" * 24), p.blob(b"\0" * 4)
    p.invoke("CreateProcessW", [p.base+executable, 0, 0, 0, 0, 0, 0, 0, p.base+startup, p.base+info])
    p.equal(1)
    p.mov(0, p.base+info); p.emit((b"\x48" if bits == 64 else b"") + b"\x8b\x18")
    p.invoke("WaitForSingleObject", [reg(3), 0xffffffff]); p.equal(0)
    p.invoke("GetExitCodeProcess", [reg(3), p.base+code]); p.equal(1)
    p.mov(0, p.base+code); p.require(b"\x81\x38" + struct.pack("<I", expected))
    p.invoke("CloseHandle", [reg(3)]); p.equal(1)
    p.mov(0, p.base+info+(bits//8)); p.emit((b"\x48" if bits == 64 else b"") + b"\x8b\x18")
    p.invoke("CloseHandle", [reg(3)]); p.equal(1)
    p.finish()
    return p


def context_probe(bits=64):
    p = Probe(["GetCommandLineW", "GetModuleFileNameW", "GetStartupInfoW", "QueryPerformanceFrequency", "QueryPerformanceCounter", "Sleep"], bits)
    buffer, startup = p.blob(b"\0" * 256), p.blob(b"\0" * 104)
    first, second = p.blob(b"\0" * 8), p.blob(b"\0" * 8)
    p.call("GetCommandLineW"); p.nonzero(); p.require(b"\x66\x83\x38\0", 0x84)
    p.invoke("GetModuleFileNameW", [0, p.base+buffer, 128]); p.nonzero()
    p.invoke("GetStartupInfoW", [p.base+startup])
    p.mov(0, p.base+startup); p.require(b"\x83\x38" + bytes([104 if bits == 64 else 68]))
    p.invoke("QueryPerformanceFrequency", [p.base+first]); p.equal(1)
    p.mov(0, p.base+first); p.emit((b"\x48" if bits == 64 else b"") + b"\x8b\x00"); p.nonzero()
    p.invoke("QueryPerformanceCounter", [p.base+first]); p.equal(1)
    p.invoke("Sleep", [1])
    p.invoke("QueryPerformanceCounter", [p.base+second]); p.equal(1)
    if bits == 64:
        p.mov(0, p.base+second); p.emit(b"\x48\x8b\x00")
        p.mov(3, p.base+first); p.require(b"\x48\x3b\x03", 0x86)
    p.finish()
    return p


class ProcessTests(unittest.TestCase):
    def run_program(self, p, root, *extra):
        exe = root.parent/"parent.exe"
        exe.write_bytes(p.image())
        return subprocess.run([str(CLI), "run", str(exe), "--root", str(root), *extra], capture_output=True, timeout=10)

    def test_child_pe_runs_in_a_separate_process_and_reports_its_real_exit(self):
        for bits in (32, 64):
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)/"drive"; root.mkdir()
                child = Probe([], bits); child.exit(37)
                (root/"child.exe").write_bytes(child.image())
                result = self.run_program(process_probe(bits), root)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_command_line_module_path_startup_and_monotonic_clock(self):
        for bits in (32, 64):
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as folder:
                result = self.run_program(context_probe(bits), Path(folder)/"drive")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_child_preserves_the_full_windows_exit_code(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/"drive"; root.mkdir()
            child = Probe([]); child.exit(0x12345678)
            (root/"child.exe").write_bytes(child.image())
            result = self.run_program(process_probe(expected=0x12345678), root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_child_sees_its_virtual_module_path_and_exact_unicode_command_line(self):
        child = Probe(["GetCommandLineW", "GetModuleFileNameW"])
        out = child.blob(b"\0"*256)
        child.call("GetCommandLineW")
        # The exact first four UTF-16 code units: quote, C, colon, backslash.
        child.mov(3, 0x005c003a00430022); child.require(b"\x48\x39\x18")
        child.invoke("GetModuleFileNameW", [0, child.base+out, 128]); child.equal(len("C:\\子程序.exe"))
        child.mov(0, child.base+out); child.require(b"\x81\x38\x43\0\x3a\0")
        child.finish()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/"drive"; root.mkdir()
            (root/"子程序.exe").write_bytes(child.image())
            p = process_probe(name="C:\\子程序.exe", expected=0)
            result = self.run_program(p, root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_spawn_depth_limit_fails_before_launching_another_child(self):
        p = Probe(["CreateProcessW", "GetLastError"])
        app = p.wide("child.exe")
        startup = p.blob(struct.pack("<I", 104)+b"\0"*100); info = p.blob(b"\0"*24)
        p.invoke("CreateProcessW", [p.base+app, 0, 0, 0, 0, 0, 0, 0, p.base+startup, p.base+info])
        p.equal(0); p.call("GetLastError"); p.equal(8); p.finish()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/"drive"; root.mkdir()
            child = Probe([]); child.exit(37); (root/"child.exe").write_bytes(child.image())
            result = self.run_program(p, root, "--process-depth", "2")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_guest_can_read_its_original_executable_without_copying_it_into_the_drive(self):
        p = Probe(["GetModuleFileNameW", "CreateFileW", "ReadFile", "CloseHandle"])
        name, data, count = p.blob(b"\0"*256), p.blob(b"\0"*4), p.blob(b"\0"*4)
        p.invoke("GetModuleFileNameW", [0, p.base+name, 128]); p.nonzero()
        p.invoke("CreateFileW", [p.base+name, 0x80000000, 1, 0, 3, 0, 0]); p.nonzero(); p.copy(3, 0)
        p.invoke("ReadFile", [reg(3), p.base+data, 2, p.base+count, 0]); p.equal(1)
        p.mov(0, p.base+data); p.require(b"\x81\x38\x4d\x5a\0\0")
        p.invoke("CloseHandle", [reg(3)]); p.equal(1)
        p.invoke("CreateFileW", [p.base+name, 0x40000000, 0, 0, 2, 0, 0]); p.equal(0xffffffff)
        p.finish()
        with tempfile.TemporaryDirectory() as folder:
            result = self.run_program(p, Path(folder)/"drive")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_or_escaping_child_paths_fail_without_spawning(self):
        for name in ("broken.exe", "..\\escape.exe", "link.exe"):
            p = Probe(["CreateProcessW", "GetLastError"])
            app = p.wide(name)
            startup = p.blob(struct.pack("<I", 104)+b"\0"*100)
            info = p.blob(b"\0"*24)
            p.invoke("CreateProcessW", [p.base+app, 0, 0, 0, 0, 0, 0, 0, p.base+startup, p.base+info])
            p.equal(0); p.call("GetLastError"); p.nonzero(); p.finish()
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)/"drive"; root.mkdir()
                (root/"broken.exe").write_bytes(b"not a PE")
                outside = Path(folder)/"escape.exe"
                child = Probe([]); child.exit(37); outside.write_bytes(child.image())
                (root/"link.exe").symlink_to(outside)
                result = self.run_program(p, root)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
