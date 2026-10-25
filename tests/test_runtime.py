import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
from build import Program, console, files

CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


class ExecutionTests(unittest.TestCase):
    def run_program(self, program, root, *extra):
        path = Path(root).parent / "program.exe"
        path.write_bytes(program.image())
        return subprocess.run([str(CLI), "run", str(path), "--root", str(root), *extra],
                              capture_output=True, timeout=5)

    def test_real_pe32_and_pe64_windows_console_calls(self):
        for bits in (32, 64):
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as directory:
                result = self.run_program(console(bits), Path(directory) / "drive_c")
                self.assertEqual(result.returncode, 37, result.stderr)
                self.assertEqual(result.stdout, b"Hello from a Windows EXE on macOS!\r\n")

    def test_windows_file_handles_write_close_reopen_read(self):
        for bits in (32, 64):
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "drive_c"
                result = self.run_program(files(bits=bits), root)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / "example.txt").read_bytes(), b"LeanWin file round trip.\n")
                self.assertEqual(result.stdout, b"LeanWin file round trip.\n")

    def test_guest_last_error_state_is_preserved(self):
        for bits in (32, 64):
            p = Program([("KERNEL32.dll", n) for n in ("SetLastError", "GetLastError", "ExitProcess")], bits)
            p.prologue()
            p.invoke("SetLastError", [79])
            p.call("GetLastError")
            p.emit(b"\x89\xc1" if bits == 64 else b"\x50")
            p.call("ExitProcess")
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as directory:
                result = self.run_program(p, Path(directory) / "drive_c")
                self.assertEqual(result.returncode, 79, result.stderr)

    def test_unimplemented_import_fails_before_guest_execution(self):
        p = Program([("KERNEL32.dll", "CreateThread")])
        p.emit(b"\xeb\xfe")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_program(p, Path(directory) / "drive_c")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"KERNEL32.dll!CreateThread", result.stderr)

    def test_instruction_budget_stops_an_infinite_guest_loop(self):
        p = Program([])
        p.emit(b"\xeb\xfe")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_program(p, Path(directory) / "drive_c", "--max-steps", "100")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"instruction budget", result.stderr)

    def test_guest_cannot_read_an_arbitrary_host_address(self):
        p = Program([])
        p.mov(0, 0xdeadbeef)
        p.emit(b"\x48\x8b\x00")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_program(p, Path(directory) / "drive_c")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"unmapped guest address", result.stderr)

    def test_unsupported_instruction_is_reported_with_guest_address(self):
        p = Program([])
        p.emit(b"\x0f\x0b")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_program(p, Path(directory) / "drive_c")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"unsupported instruction", result.stderr)
            self.assertIn(b"140001000", result.stderr)

    def test_file_paths_cannot_escape_via_dotdot_or_parent_symlink(self):
        for name in ("..\\escape.txt", "link\\escape.txt"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                root, outside = base / "drive_c", base / "outside"
                root.mkdir(); outside.mkdir()
                (root / "link").symlink_to(outside, target_is_directory=True)
                p = Program([("KERNEL32.dll", n) for n in ("CreateFileW", "GetLastError", "ExitProcess")])
                name_rva = p.wide(name)
                p.prologue()
                p.invoke("CreateFileW", [p.base + name_rva, 0x40000000, 0, 0, 2, 0x80, 0])
                p.call("GetLastError")
                p.emit(b"\x89\xc1")
                p.call("ExitProcess")
                result = self.run_program(p, root)
                self.assertEqual(result.returncode, 5, result.stderr)
                self.assertFalse((base / "escape.txt").exists())
                self.assertFalse((outside / "escape.txt").exists())

    def test_report_records_actual_steps_and_guest_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            result = self.run_program(console(), Path(directory) / "drive_c", "--report", str(report))
            self.assertEqual(result.returncode, 37, result.stderr)
            data = json.loads(report.read_text())
            self.assertEqual(data["guest_exit_code"], 37)
            self.assertEqual(data["backend"], "original-x86-interpreter")
            self.assertGreater(data["instructions"], 0)
            self.assertGreaterEqual(data["elapsed_ms"], 0)
            self.assertIn("host_peak_rss_bytes", data)
            self.assertGreater(data["host_peak_rss_bytes"], 0)

    def test_create_file_does_not_block_on_a_fifo_in_the_guest_drive(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("requires a POSIX FIFO")
        p = Program([("KERNEL32.dll", n) for n in ("CreateFileW", "GetLastError", "ExitProcess")])
        name = p.wide("pipe")
        p.prologue()
        p.invoke("CreateFileW", [p.base + name, 0x40000000, 0, 0, 3, 0x80, 0])
        p.call("GetLastError")
        p.emit(b"\x89\xc1")
        p.call("ExitProcess")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "drive_c"
            root.mkdir()
            os.mkfifo(root / "pipe")
            try:
                result = self.run_program(p, root)
            except subprocess.TimeoutExpired:
                self.fail("CreateFileW blocked on a FIFO instead of rejecting a non-regular file")
            self.assertEqual(result.returncode, 5, result.stderr)

    def test_create_always_reports_that_an_existing_file_was_replaced(self):
        p = Program([("KERNEL32.dll", n) for n in ("CreateFileW", "GetLastError", "ExitProcess")])
        name = p.wide("existing.txt")
        p.prologue()
        p.invoke("CreateFileW", [p.base + name, 0x40000000, 0, 0, 2, 0x80, 0])
        p.call("GetLastError")
        p.emit(b"\x89\xc1")
        p.call("ExitProcess")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "drive_c"
            root.mkdir()
            (root / "existing.txt").write_text("old contents")
            result = self.run_program(p, root)
            self.assertEqual(result.returncode, 183, result.stderr)
            self.assertEqual((root / "existing.txt").read_bytes(), b"")

    def test_loader_module_handles_and_dynamic_procedure_calls(self):
        names = ("LoadLibraryW", "GetProcAddress", "GetLastError", "ExitProcess")
        p = Program([("KERNEL32.dll", n) for n in names])
        library, proc = p.wide("kernel32.dll"), p.blob(b"SetLastError\0")
        p.prologue()
        p.invoke("LoadLibraryW", [p.base + library])
        p.emit(b"\x48\x89\xc1")
        p.argument(1, p.base + proc)
        p.call("GetProcAddress")
        p.save_handle()
        p.argument(0, 91)
        p.emit(b"\xff\xd3")
        p.call("GetLastError")
        p.emit(b"\x89\xc1")
        p.call("ExitProcess")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_program(p, Path(directory) / "drive_c")
            self.assertEqual(result.returncode, 91, result.stderr)

    def test_file_size_output_is_a_windows_64_bit_integer(self):
        names = ("CreateFileW", "GetFileSizeEx", "ExitProcess")
        p = Program([("KERNEL32.dll", n) for n in names])
        name, output = p.wide("existing.txt"), p.blob(b"\0" * 8)
        p.prologue()
        p.invoke("CreateFileW", [p.base + name, 0x80000000, 0, 0, 3, 0x80, 0])
        p.handle_call("GetFileSizeEx", [p.base + output], register=0)
        p.mov(0, p.base + output)
        p.emit(b"\x8b\x08")
        p.call("ExitProcess")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "drive_c"
            root.mkdir()
            (root / "existing.txt").write_bytes(b"x" * 129)
            result = self.run_program(p, root)
            self.assertEqual(result.returncode, 129, result.stderr)

    def test_exclusive_file_open_rejects_a_second_open_without_truncation(self):
        p = Program([("KERNEL32.dll", n) for n in ("CreateFileW", "GetLastError", "ExitProcess")])
        name = p.wide("existing.txt")
        p.prologue()
        p.invoke("CreateFileW", [p.base + name, 0x80000000, 0, 0, 3, 0x80, 0])
        p.invoke("CreateFileW", [p.base + name, 0x40000000, 0, 0, 2, 0x80, 0])
        p.call("GetLastError")
        p.emit(b"\x89\xc1")
        p.call("ExitProcess")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "drive_c"
            root.mkdir()
            (root / "existing.txt").write_bytes(b"keep these bytes")
            result = self.run_program(p, root)
            self.assertEqual(result.returncode, 32, result.stderr)
            self.assertEqual((root / "existing.txt").read_bytes(), b"keep these bytes")

    def test_32_bit_arpl_is_rejected_instead_of_decoding_as_64_bit_movsxd(self):
        p = Program([("KERNEL32.dll", "ExitProcess")], 32)
        p.mov(0, 79)
        p.emit(b"\x63\xc0\x50")
        p.call("ExitProcess")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_program(p, Path(directory) / "drive_c")
            self.assertIn(b"unsupported instruction", result.stderr)

    def test_unsigned_carry_signed_overflow_and_zero_control_branches(self):
        cases = [(0xffffffff, 1, 0x72), (0x7fffffff, 1, 0x70), (1, 0xffffffff, 0x74)]
        for first, second, branch in cases:
            p = Program([("KERNEL32.dll", "ExitProcess")])
            p.prologue()
            p.emit(b"\xb8" + struct.pack("<I", first))
            p.emit(b"\xba" + struct.pack("<I", second))
            p.emit(b"\x01\xd0")
            # Skip the first MOV when the independently expected condition holds.
            p.emit(bytes([branch, 12]))
            p.mov(1, 99)
            p.emit(b"\xeb\x0a")
            p.mov(1, 17)
            p.call("ExitProcess")
            with self.subTest(first=first, branch=branch), tempfile.TemporaryDirectory() as directory:
                result = self.run_program(p, Path(directory) / "drive_c")
                self.assertEqual(result.returncode, 17, result.stderr)

    def test_windows_wide_paths_preserve_chinese_and_surrogate_pairs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "drive_c"
            result = self.run_program(files("资料🐋.txt"), root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "资料🐋.txt").read_bytes(), b"LeanWin file round trip.\n")

    def test_process_clock_and_main_module_interfaces_return_host_backed_values(self):
        for name in ("GetCurrentProcessId", "GetTickCount64", "GetModuleHandleW"):
            p = Program([("KERNEL32.dll", n) for n in (name, "GetStdHandle", "WriteFile", "ExitProcess")])
            output, written = p.blob(b"\0" * 8), p.blob(b"\0" * 8)
            p.prologue()
            p.invoke(name, [0] if name == "GetModuleHandleW" else [])
            p.mov(3, p.base + output)
            p.emit(b"\x48\x89\x03")
            p.invoke("GetStdHandle", [-11])
            p.handle_call("WriteFile", [p.base + output, 8, p.base + written, 0], register=0)
            p.exit(0)
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "program.exe"
                path.write_bytes(p.image())
                # Python 3.9 macOS monotonic() has a process-local epoch.
                # CLOCK_MONOTONIC is the host boot-relative clock exposed here.
                before = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
                process = subprocess.Popen([str(CLI), "run", str(path), "--root", str(Path(directory) / "drive_c")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output_bytes, error = process.communicate(timeout=5)
                after = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
                self.assertEqual(process.returncode, 0, error)
                self.assertEqual(len(output_bytes), 8)
                value = struct.unpack("<Q", output_bytes)[0]
                if name == "GetCurrentProcessId":
                    self.assertEqual(value, process.pid)
                elif name == "GetModuleHandleW":
                    self.assertEqual(value, 0x140000000)
                else:
                    self.assertLessEqual(before - 1000, value)
                    self.assertLessEqual(value, after + 1000)

    def test_unsupported_message_box_flags_return_a_windows_error_without_opening_ui(self):
        p = Program([("USER32.dll", "MessageBoxW"), ("KERNEL32.dll", "GetLastError"), ("KERNEL32.dll", "ExitProcess")])
        p.prologue()
        p.invoke("MessageBoxW", [0, 0, 0, 4])
        p.call("GetLastError")
        p.emit(b"\x89\xc1")
        p.call("ExitProcess")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_program(p, Path(directory) / "drive_c")
            self.assertEqual(result.returncode, 50, result.stderr)


if __name__ == "__main__":
    unittest.main()
