import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT/"build/leanwin"))


class StartupInstructionTests(unittest.TestCase):
    def run_probe(self, p):
        with tempfile.TemporaryDirectory() as folder:
            exe = Path(folder)/"cpu.exe"; exe.write_bytes(p.image())
            return subprocess.run([str(CLI), "run", str(exe), "--root", str(Path(folder)/"drive")], capture_output=True, timeout=5)

    def test_push_pop_flags_preserve_id_and_direction_across_arithmetic(self):
        for bits in (32, 64):
            p = Probe([], bits)
            p.emit(b"\x68\x02\x04\x20\0\x9d") # ID + DF + reserved bit 1.
            p.mov(0, 2); p.emit(b"\x83\xc0\x01\x9c\x58")
            p.emit(b"\x25\0\x04\x20\0"); p.equal(0x200400)
            p.emit(b"\x6a\x02\x9d\x9c\x58\x25\0\x04\x20\0"); p.equal(0)
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_probe(p); self.assertEqual(result.returncode, 0, result.stderr)

    def test_cpuid_describes_an_integer_interpreter_without_simd_features(self):
        p = Probe([])
        p.mov(0, 0); p.emit(b"\x0f\xa2"); p.equal(1)
        p.copy(0, 3); p.equal(0x6e61654c) # "Lean" vendor prefix.
        p.mov(0, 1); p.emit(b"\x0f\xa2")
        p.copy(0, 1); p.equal(0); p.copy(0, 2); p.equal(0)
        p.finish()
        result = self.run_probe(p); self.assertEqual(result.returncode, 0, result.stderr)

    def test_accumulator_and_byte_immediates_and_test_set_real_flags(self):
        for bits in (32, 64):
            p = Probe([], bits)
            slot = p.blob(b"\x5a\xcc\xcc\xcc")
            p.mov(0, 0x12345678); p.emit(b"\x35\x78\x56\x34\x12"); p.equal(0)
            p.mov(3, p.base+slot); p.emit(b"\x80\x3b\x5a"); p.require(b"")
            p.emit(b"\x80\x03\x01"); p.require(b"\x81\x3b\x5b\xcc\xcc\xcc")
            p.mov(2, 0x2000000); p.emit(b"\xf7\xc2\0\0\0\x02"); p.require(b"", 0x84)
            p.emit(b"\xf6\x03\x01"); p.require(b"", 0x84)
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_probe(p); self.assertEqual(result.returncode, 0, result.stderr)

    def test_stos_uses_accumulator_width_and_clear_direction_flag(self):
        for bits in (32, 64):
            p = Probe([], bits)
            target = p.blob(b"\0"*16)
            p.mov(0, 0x11223344); p.mov(7, p.base+target); p.mov(1, 2)
            p.emit(b"\xfc\xf3\xab")
            p.mov(3, p.base+target); p.require(b"\x81\x3b\x44\x33\x22\x11")
            p.require(b"\x81\x7b\x04\x44\x33\x22\x11")
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_probe(p); self.assertEqual(result.returncode, 0, result.stderr)

    def test_signed_multiply_truncation_overflow_and_logical_arithmetic_shifts(self):
        for bits in (32, 64):
            p = Probe([], bits)
            p.mov(0, 7); p.emit(b"\x69\xc0\x03\0\0\0"); p.equal(21)
            p.emit(b"\x6b\xc0\xfe"); p.equal(0xffffffd6)
            p.mov(0, 0x40000000); p.mov(3, 4); p.emit(b"\x0f\xaf\xc3"); p.require(b"", 0x81)
            p.equal(0)
            p.mov(0, 0x80000000); p.emit(b"\xd1\xe8"); p.equal(0x40000000)
            p.mov(0, 0x80000000); p.emit(b"\xc1\xf8\x04"); p.equal(0xf8000000)
            p.mov(0, 3); p.mov(1, 4); p.emit(b"\xd3\xe0"); p.equal(48)
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_probe(p); self.assertEqual(result.returncode, 0, result.stderr)

    def test_string_moves_copy_forward_backward_and_repeat_without_changing_flags(self):
        for bits in (32, 64):
            p = Probe([], bits)
            source, target = p.blob(b"abcdefgh"), p.blob(b"\0"*16)
            p.mov(6, p.base+source); p.mov(7, p.base+target); p.mov(1, 2)
            p.emit(b"\xf3\xa5")
            p.mov(3, p.base+target); p.require(b"\x81\x3b"+b"abcd")
            p.require(b"\x81\x7b\x04"+b"efgh")
            p.mov(6, p.base+source+7); p.mov(7, p.base+target+15); p.mov(1, 8)
            p.emit(b"\x68\x02\x04\0\0\x9d\xf3\xa4\x6a\x02\x9d")
            p.mov(3, p.base+target+8); p.require(b"\x81\x3b"+b"abcd"); p.require(b"\x81\x7b\x04"+b"efgh")
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_probe(p); self.assertEqual(result.returncode, 0, result.stderr)
