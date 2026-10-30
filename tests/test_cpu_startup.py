import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT/"build/leanwin"))


def byte_immediate_probe(bits=64):
    p=Probe([],bits)
    initial=0x1122334455667788 if bits==64 else 0x55667788
    for code in range(8):
        target=code if code<4 else code-4
        p.mov(target,initial)
        p.emit(bytes([0xb0+code,0xa5]))
        p.copy(0,target)
        expected=(initial & ~0xff)|0xa5 if code<4 else (initial & ~0xff00)|0xa500
        p.mov(2,expected)
        p.require((b"\x48" if bits==64 else b"")+b"\x39\xd0")
    if bits==64:
        # A bare REX selects SIL rather than DH; REX.B selects r8b..r15b.
        for target in (5,6,7,*range(8,16)):
            p.mov(target,initial)
            p.emit(bytes([0x41 if target>=8 else 0x40,0xb0+(target & 7),0x5a]))
            p.copy(0,target); p.mov(2,(initial & ~0xff)|0x5a); p.require(b"\x48\x39\xd0")
        p.copy(6,4); p.emit(b"\x40\xb4\x5a"); p.copy(0,4); p.copy(4,6)
        p.emit(b"\x25\xff\0\0\0"); p.equal(0x5a)
    # MOV must leave the carry flag from CMP unchanged.
    p.mov(0,0); p.emit(b"\x83\xf8\x01\xb2\x01"); p.require(b"",0x83)
    p.finish(); return p


def repeat_return_probe(bits=64):
    p=Probe([],bits); calls=[]
    for count in (0,3):
        p.mov(1,count); p.mov(0,0); p.emit(b"\x83\xf8\x01\xe8\0\0\0\0")
        calls.append(len(p.code)-4)
        p.require(b"",0x83); p.equal(42)
        p.copy(0,1); p.equal(count)
    p.finish(); target=len(p.code)
    p.mov(0,42); p.emit(b"\xf3\xc3")
    for offset in calls: struct.pack_into("<i",p.code,offset,target-offset-4)
    return p


def scan_probe(bits=64):
    p=Probe([],bits)
    for width in (1,2,4,*([8] if bits==64 else [])):
        data=p.blob(b"".join(n.to_bytes(width,"little") for n in (7,7,9,0)))
        suffix=(b"\x66" if width==2 else b"\x48" if width==8 else b"")+bytes([0xae if width==1 else 0xaf])
        for prefix,value,count,consumed,zero,backward in [
                (b"\xf2",9,4,3,True,False),
                (b"\xf3",7,4,3,False,False),
                (b"\xf2",8,2,2,False,False),
                (b"\xf2",7,4,2,True,True),
                (b"",7,4,1,True,False)]:
            start=p.base+data+(2*width if backward else 0)
            p.mov(0,value); p.mov(7,start); p.mov(1,count)
            p.emit(b"\x68"+struct.pack("<I",0x402 if backward else 0x202)+b"\x9d")
            p.emit(prefix+suffix)
            p.require(b"",0x85 if zero else 0x84)
            p.emit(b"\xfc"); p.copy(0,1); p.equal(count-consumed if prefix else count)
            p.copy(0,7); p.mov(2,start+(-consumed if backward else consumed)*width)
            p.require((b"\x48" if bits==64 else b"")+b"\x39\xd0")
    # Zero-count REP must neither access an invalid destination nor change flags.
    p.mov(7,1); p.mov(1,0); p.mov(0,0)
    p.emit(b"\x83\xf8\x01\xf2\xae"); p.require(b"",0x83)
    p.finish(); return p


def not_probe(bits=64):
    p=Probe([],bits); data=p.blob(b"\x12\x34\x56\x78\x9a\xbc\xde\xf0")
    p.mov(0,0); p.emit(b"\x83\xf8\x01")
    p.mov(1,0x12345678); p.emit(b"\xf7\xd1"); p.require(b"",0x83)
    p.copy(0,1); p.equal(0xedcba987)
    p.mov(1,0x12345678); p.emit(b"\x66\xf7\xd1"); p.copy(0,1); p.equal(0x1234a987)
    p.mov(3,p.base+data); p.emit(b"\xf6\x13"); p.require(b"\x81\x3b\xed\x34\x56\x78")
    if bits==64:
        p.mov(9,0x0123456789abcdef); p.emit(b"\x49\xf7\xd1"); p.copy(0,9)
        p.mov(2,0xfedcba9876543210); p.require(b"\x48\x39\xd0")
    p.finish(); return p


class StartupInstructionTests(unittest.TestCase):
    def run_probe(self, p, max_steps=1000000):
        with tempfile.TemporaryDirectory() as folder:
            exe = Path(folder)/"cpu.exe"; exe.write_bytes(p.image())
            return subprocess.run([str(CLI), "run", str(exe), "--root", str(Path(folder)/"drive"),
                "--max-steps",str(max_steps)], capture_output=True, timeout=5)

    def test_byte_immediates_preserve_other_bits_flags_and_rex_register_selection(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(byte_immediate_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_rep_ret_returns_once_without_consuming_count_or_changing_flags(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(repeat_return_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_string_scans_stop_on_equality_mismatch_count_and_direction(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(scan_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_not_preserves_flags_and_complements_only_the_operand_width(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(not_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_repeated_scan_checks_page_boundary_and_instruction_budget(self):
        p=Probe(["VirtualAlloc"])
        p.invoke("VirtualAlloc",[0,4096,0x3000,4]); p.nonzero(); p.copy(7,0)
        p.mov(0,1); p.mov(1,5000); p.emit(b"\xf2\xae"); p.exit(99)
        r=self.run_probe(p); self.assertEqual(r.returncode,65,r.stderr); self.assertIn(b"protection violation",r.stderr)
        r=self.run_probe(p,100); self.assertEqual(r.returncode,65,r.stderr); self.assertIn(b"instruction budget exhausted",r.stderr)

    def test_adc_and_sbb_consume_carry_and_produce_overflow_and_borrow(self):
        for bits in (32,64):
            p=Probe([],bits)
            p.mov(0,0); p.emit(b"\x83\xf8\x01\x1b\xc0"); p.equal(0xffffffff)
            p.mov(0,0x7fffffff); p.mov(3,0)
            p.emit(b"\x83\xfb\x01\x13\xc3"); p.require(b"",0x81); p.equal(0x80000000)
            p.mov(0,0xffffffff); p.mov(3,0)
            p.emit(b"\x83\xfb\x01\x83\xd0\0"); p.require(b"",0x83); p.equal(0)
            p.mov(0,0x80000000); p.mov(3,0x7fffffff)
            p.mov(1,0); p.emit(b"\x83\xf9\x01\x1b\xc3"); p.require(b"",0x81); p.equal(0)
            p.finish()
            with self.subTest(bits=bits):
                r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_unsigned_division_uses_the_double_width_dividend(self):
        for bits in (32,64):
            p=Probe([],bits); p.mov(0,10); p.mov(2,1); p.mov(3,3)
            p.emit(b"\xf7\xf3"); p.equal(1431655768); p.copy(0,2); p.equal(2)
            if bits==64:
                p.mov(0,0); p.mov(2,1); p.mov(3,3); p.emit(b"\x48\xf7\xf3")
                p.mov(3,0x5555555555555555); p.require(b"\x48\x39\xd8")
                p.copy(0,2); p.equal(1)
            p.finish()
            with self.subTest(bits=bits):
                r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_division_by_zero_and_quotient_overflow_stop_the_guest(self):
        for high,divisor in [(0,0),(3,3)]:
            p=Probe([]); p.mov(0,10); p.mov(2,high); p.mov(3,divisor); p.emit(b"\xf7\xf3"); p.exit(0)
            with self.subTest(high=high,divisor=divisor):
                r=self.run_probe(p); self.assertEqual(r.returncode,65); self.assertIn(b"divide",r.stderr)

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
