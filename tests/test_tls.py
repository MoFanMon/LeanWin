"""Execute independently assembled TLS images through the real command line."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
from build import Program, DATA, TEXT

CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


class TLSProgram(Program):
    def __init__(self, bits=64, imports=()):
        super().__init__(imports, bits)
        self.word = bits // 8
        self.template = self.blob(b"\x11\x22\x33\x44")
        self.index = self.blob(b"\xff" * 4)
        self.callback_table = self.blob(b"\0" * (self.word * 66))
        self.callbacks = []
        self.tls = self.blob(struct.pack("<QQQQII" if bits == 64 else "<IIIIII",
            self.base + self.template, self.base + self.template + 4,
            self.base + self.index, self.base + self.callback_table, 8, 0x00e00000))
        self.failures = []

    def image(self):
        image = super().image()
        directories = 0x98 + (112 if self.bits == 64 else 96)
        struct.pack_into("<II", image, directories + 9 * 8, self.tls, 40 if self.bits == 64 else 24)
        return image

    def tls_pointer(self):
        # MOV RAX, GS:[0x58] / MOV EAX, FS:[0x2c], then select _tls_index.
        self.emit(b"\x65\x48\x8b\x04\x25\x58\0\0\0" if self.bits == 64 else b"\x64\xa1\x2c\0\0\0")
        self.mov(2, self.base + self.index)
        self.emit(b"\x8b\x0a")
        self.emit(b"\x48\x8b\x04\xc8" if self.bits == 64 else b"\x8b\x04\x88")

    def require_equal(self, comparison):
        self.emit(comparison + b"\x0f\x85\0\0\0\0")
        self.failures.append(len(self.code) - 4)

    def finish(self, value=42):
        self.mov(0, value)
        self.emit(b"\xc3")
        fail = len(self.code)
        self.mov(0, 99)
        self.emit(b"\xc3")
        for offset in self.failures:
            struct.pack_into("<i", self.code, offset, fail - offset - 4)

    def callback(self):
        address = self.base + TEXT + len(self.code)
        struct.pack_into("<Q" if self.bits == 64 else "<I", self.data,
                         self.callback_table - DATA + len(self.callbacks) * self.word, address)
        self.callbacks.append(address)

    def callback_return(self):
        self.emit(b"\xc3" if self.bits == 64 else b"\xc2\x0c\0")


class TLSTests(unittest.TestCase):
    def run_image(self, image, *extra):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tls.exe"
            path.write_bytes(image)
            return subprocess.run([str(CLI), "run", str(path), "--root",
                str(Path(directory) / "drive"), *extra], capture_output=True, timeout=5)

    def test_static_tls_template_is_copied_zero_filled_and_independently_writable(self):
        # Missing initialization, wrong index/segment addressing, or aliasing the
        # PE template instead of copying it must change the guest's result.
        for bits in (32, 64):
            p = TLSProgram(bits)
            p.tls_pointer()
            p.require_equal(b"\x81\x38\x11\x22\x33\x44")
            p.require_equal(b"\x81\x78\x04\0\0\0\0")
            p.require_equal(b"\x81\x78\x08\0\0\0\0")
            p.emit(b"\xc7\x00\x5a\0\0\0")
            p.mov(0, p.base + p.template)
            p.require_equal(b"\x81\x38\x11\x22\x33\x44")
            p.tls_pointer()
            p.require_equal(b"\x81\xe0\xff\x1f\0\0\x83\xf8\0")
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_image(p.image())
                self.assertEqual(result.returncode, 42, result.stderr)

    def test_callback_receives_module_reason_reserved_and_windows_stack_alignment(self):
        for bits in (32, 64):
            p = TLSProgram(bits)
            observed = p.blob(b"\0" * 4)
            p.mov(0, p.base + observed)
            p.emit(b"\x8b\x00\xc3")
            p.callback()
            if bits == 64:
                p.mov(0, p.base)
                p.require_equal(b"\x48\x39\xc1")  # RCX == module
                p.require_equal(b"\x83\xfa\x01")  # EDX == PROCESS_ATTACH
                p.require_equal(b"\x49\x83\xf8\0")  # R8 == NULL
                p.emit(b"\x48\x89\xe0\x83\xe0\x0f")
                p.require_equal(b"\x83\xf8\x08")
                # The callback may use the caller-provided shadow space.
                p.emit(b"\x48\xc7\x44\x24\x08\x37\0\0\0")
            else:
                for offset, expected in ((4, p.base), (8, 1), (12, 0)):
                    p.require_equal(b"\x81\x7c\x24" + bytes([offset]) + struct.pack("<I", expected))
            p.mov(0, p.base + observed)
            p.emit(b"\xc7\x00\x49\0\0\0")
            p.callback_return()
            fail = len(p.code)
            p.mov(0, p.base + observed)
            p.emit(b"\xc7\x00\x63\0\0\0")
            p.callback_return()
            for offset in p.failures:
                struct.pack_into("<i", p.code, offset, fail - offset - 4)
            with self.subTest(bits=bits):
                result = self.run_image(p.image())
                self.assertEqual(result.returncode, 73, result.stderr)

    def test_callbacks_run_in_table_order_and_share_tls_with_entry_point(self):
        for bits in (32, 64):
            p = TLSProgram(bits)
            p.tls_pointer()
            p.emit(b"\x8b\x00\xc3")
            p.callback()
            p.tls_pointer()
            p.emit(b"\xc7\x00\x07\0\0\0")
            p.callback_return()
            p.callback()
            p.tls_pointer()
            p.emit(b"\x83\x00\x05")
            p.callback_return()
            with self.subTest(bits=bits):
                result = self.run_image(p.image())
                self.assertEqual(result.returncode, 12, result.stderr)

    def test_exit_process_in_callback_prevents_entry_point_execution(self):
        for bits in (32, 64):
            p = TLSProgram(bits, [("KERNEL32.dll", "ExitProcess")])
            p.emit(b"\x0f\x0b")  # Must never reach this entry point.
            p.callback()
            p.prologue()
            p.exit(23)
            with self.subTest(bits=bits):
                result = self.run_image(p.image())
                self.assertEqual(result.returncode, 23, result.stderr)

    def test_callback_infinite_loop_uses_the_global_instruction_budget(self):
        p = TLSProgram()
        p.finish()
        p.callback()
        p.emit(b"\xeb\xfe")
        result = self.run_image(p.image(), "--max-steps", "20")
        self.assertEqual(result.returncode, 65)
        self.assertIn(b"instruction budget", result.stderr)

    def test_callback_and_entry_point_share_one_instruction_budget(self):
        p = TLSProgram()
        p.finish()
        p.callback()
        p.emit(b"\x90" * 5 + b"\xc3")
        result = self.run_image(p.image(), "--max-steps", "7")
        self.assertEqual(result.returncode, 65)
        self.assertIn(b"instruction budget", result.stderr)

    def test_empty_tls_template_and_callback_list_can_initialize(self):
        for bits in (32, 64):
            for null_callbacks in (False, True):
                p = TLSProgram(bits)
                # A callback-only PE may have no initialized TLS bytes at all.
                struct.pack_into("<QQ" if bits == 64 else "<II", p.data, p.tls - DATA, 0, 0)
                if null_callbacks:
                    struct.pack_into("<Q" if bits == 64 else "<I", p.data, p.tls - DATA + p.word * 3, 0)
                p.tls_pointer()
                p.require_equal(b"\x81\x38\0\0\0\0")
                p.finish()
                with self.subTest(bits=bits, null_callbacks=null_callbacks):
                    result = self.run_image(p.image())
                    self.assertEqual(result.returncode, 42, result.stderr)

    def test_segment_override_does_not_change_lea_result(self):
        p = TLSProgram()
        p.emit(b"\x65\x48\x8d\x04\x25\x58\0\0\0\xc3")
        result = self.run_image(p.image())
        self.assertEqual(result.returncode, 88, result.stderr)

    def test_malformed_tls_is_rejected_before_any_callback_runs(self):
        for bits in (32, 64):
            p = TLSProgram(bits, [("KERNEL32.dll", "ExitProcess")])
            p.finish()
            p.callback()
            p.prologue()
            p.exit(23)
            original = p.image()
            directory = 0x600 + p.tls - DATA
            optional_dirs = 0x98 + (112 if bits == 64 else 96)
            word = bits // 8
            cases = []
            for field in (0, 2, 3):
                data = bytearray(original)
                struct.pack_into("<Q" if bits == 64 else "<I", data, directory + word * field, 0xdeadbeef)
                cases.append((f"invalid VA field {field}", data))
            data = bytearray(original)
            struct.pack_into("<Q" if bits == 64 else "<I", data, directory + word, p.base + p.template - 1)
            cases.append(("reversed template range", data))
            data = bytearray(original)
            struct.pack_into("<I", data, optional_dirs + 9 * 8 + 4, 1)
            cases.append(("short directory", data))
            data = bytearray(original)
            struct.pack_into("<I", data, directory + word * 4, 0xffffffff)
            cases.append(("excessive zero fill", data))
            data = bytearray(original)
            struct.pack_into("<I", data, directory + word * 4 + 4, 0x00f00000)
            cases.append(("invalid alignment", data))
            data = bytearray(original)
            struct.pack_into("<Q" if bits == 64 else "<I", data, 0x600 + p.callback_table - DATA, p.base + p.template)
            cases.append(("non-executable callback", data))
            data = bytearray(original)
            for i in range(65):
                struct.pack_into("<Q" if bits == 64 else "<I", data,
                    0x600 + p.callback_table - DATA + i * word, p.callbacks[0])
            cases.append(("unterminated callback list", data))
            for label, data in cases:
                with self.subTest(bits=bits, case=label):
                    result = self.run_image(data)
                    self.assertEqual(result.returncode, 65, result.stderr)
                    self.assertIn(b"TLS", result.stderr)


if __name__ == "__main__":
    unittest.main()
