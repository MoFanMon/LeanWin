"""Real PE probes for the SIMD data movement used by installer startup."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe, reg

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


def check_lanes(p, address, values):
    p.mov(3, address)
    for i, value in enumerate(values):
        p.require((b"\x81\x3b" if not i else b"\x81\x7b"+bytes([i*4]))+struct.pack("<I", value))


def simd_probe(bits=64):
    p = Probe([], bits)
    # Deliberately unaligned: MOVUPS must not impose MOVAPS's alignment.
    source, out = p.blob(b"X"+struct.pack("<IIII", 1, 2, 3, 4)), p.blob(b"\xcc"*24)
    p.mov(0, p.base+source+1); p.emit(b"\x0f\x10\x00")
    p.emit(b"\x66\x0f\x70\xc8\x1b") # PSHUFD xmm1,xmm0: reverse all four lanes.
    p.mov(0, p.base+out+1); p.emit(b"\x0f\x11\x08")
    check_lanes(p, p.base+out+1, [4, 3, 2, 1])
    p.mov(1, 0x11223344); p.emit(b"\x66\x0f\x6e\xc1")
    p.mov(0, p.base+out); p.emit(b"\x0f\x11\x00")
    check_lanes(p, p.base+out, [0x11223344, 0, 0, 0])
    p.emit(b"\x66\x0f\x70\xc0\0")
    p.mov(0, p.base+out); p.emit(b"\x0f\x11\x00")
    check_lanes(p, p.base+out, [0x11223344]*4)
    vector=p.blob(b"\0"*32); address=(p.base+vector+15)&~15
    struct.pack_into("<IIII",p.data,address-p.base-0x2000,1,2,3,4)
    operand=address-(p.base+0x1000+len(p.code)+9) if bits==64 else address
    p.emit(b"\x66\x0f\x70\x15"+struct.pack("<i" if bits==64 else "<I",operand)+b"\xb1")
    p.mov(0,p.base+out); p.emit(b"\x0f\x11\x10")
    check_lanes(p,p.base+out,[2,1,4,3])
    p.finish()
    return p


def aligned_simd_probe(bits=64):
    p=Probe([],bits); slot=p.blob(b"\0"*48)
    aligned=(p.base+slot+15)&~15
    p.mov(0,73); p.emit(b"\x66\x0f\x6e\xc0\x0f\x28\xc8")
    p.mov(0,aligned); p.emit(b"\x0f\x29\x08\x0f\x28\x10\x66\x0f\x7e\xd0")
    p.equal(73); p.finish(); return p


class SIMDTests(unittest.TestCase):
    def run_probe(self, p, *extra):
        with tempfile.TemporaryDirectory() as folder:
            exe = Path(folder)/"simd.exe"; exe.write_bytes(p.image())
            return subprocess.run([str(CLI), "run", str(exe), "--root", str(Path(folder)/"drive"), *extra], capture_output=True, timeout=5)

    def test_installer_movd_shuffle_and_unaligned_copy_preserve_all_lanes(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                r = self.run_probe(simd_probe(bits)); self.assertEqual(r.returncode, 0, r.stderr)

    def test_movaps_register_and_aligned_memory_round_trip(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                r=self.run_probe(aligned_simd_probe(bits)); self.assertEqual(r.returncode, 0, r.stderr)

    def test_movd_store_writes_four_bytes_and_zero_extends_a_32_bit_register(self):
        p=Probe([]); slot=p.blob(b"\xcc"*16)
        p.mov(0, 0x8877665544332211); p.emit(b"\x66\x0f\x6e\xc0")
        p.mov(3, p.base+slot); p.emit(b"\x66\x0f\x7e\x03")
        check_lanes(p, p.base+slot, [0x44332211, 0xcccccccc, 0xcccccccc, 0xcccccccc])
        p.mov(0, 0xffffffffffffffff); p.emit(b"\x66\x0f\x7e\xc0")
        p.mov(3, 0x44332211); p.require(b"\x48\x39\xd8"); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode, 0, r.stderr)

    def test_movq_and_extended_xmm_registers_keep_the_full_64_bits(self):
        p=Probe([]); slot=p.blob(b"\xcc"*16)
        p.mov(9, 0x8877665544332211); p.emit(b"\x66\x4d\x0f\x6e\xc1") # xmm8 <- r9.
        p.mov(0, p.base+slot); p.emit(b"\x44\x0f\x11\x00")
        check_lanes(p, p.base+slot, [0x44332211, 0x88776655, 0, 0])
        p.emit(b"\x66\x4d\x0f\x7e\xc2"); p.mov(0, 0x8877665544332211)
        p.require(b"\x4c\x39\xd0"); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode, 0, r.stderr)

    def test_movaps_rejects_misaligned_memory(self):
        p=Probe([]); slot=p.blob(b"\0"*32)
        p.mov(0, ((p.base+slot+15)&~15)+1); p.emit(b"\x0f\x28\x00"); p.exit(0)
        r=self.run_probe(p); self.assertEqual(r.returncode, 65); self.assertIn(b"align", r.stderr)

    def test_legacy_pshufd_rejects_misaligned_memory(self):
        p=Probe([]); slot=p.blob(b"\0"*32)
        p.mov(0,((p.base+slot+15)&~15)+1); p.emit(b"\x66\x0f\x70\x00\0"); p.exit(0)
        r=self.run_probe(p); self.assertEqual(r.returncode,65); self.assertIn(b"align",r.stderr)

    def test_vector_store_obeys_guest_page_protection(self):
        p=Probe(["VirtualAlloc"])
        p.invoke("VirtualAlloc", [0,4096,0x3000,2]); p.emit(b"\x0f\x11\x00"); p.exit(0)
        r=self.run_probe(p); self.assertEqual(r.returncode,65); self.assertIn(b"protection",r.stderr)

    def test_vector_load_checks_the_whole_operand_across_a_page_boundary(self):
        p=Probe(["VirtualAlloc"])
        p.invoke("VirtualAlloc", [0,4096,0x3000,4]); p.emit(b"\x48\x05\xf8\x0f\0\0\x0f\x10\x00"); p.exit(0)
        r=self.run_probe(p); self.assertEqual(r.returncode,65); self.assertIn(b"guest address",r.stderr)

    def test_scalar_float_prefix_is_not_silently_treated_as_packed_move(self):
        p=Probe([]); p.emit(b"\xf3\x0f\x10\xc0"); p.exit(0)
        r=self.run_probe(p); self.assertEqual(r.returncode,65)

    def test_xmm_registers_are_independent_across_guest_thread_switches(self):
        p=Probe(["CreateThread","WaitForSingleObject","GetExitCodeThread"])
        start, code=p.blob(b"\0"*8),p.blob(b"\0"*4)
        p.mov(0,17); p.emit(b"\x66\x0f\x6e\xf0") # xmm6 is nonvolatile in Windows x64.
        p.mov(0,p.base+start); p.emit(b"\x48\x8b\x38")
        p.invoke("CreateThread",[0,0,reg(7),0,0,0]); p.copy(3,0)
        p.invoke("WaitForSingleObject",[reg(3),0xffffffff]); p.equal(0)
        p.invoke("GetExitCodeThread",[reg(3),p.base+code]); p.equal(1)
        p.mov(0,p.base+code); p.require(b"\x83\x38\0")
        p.emit(b"\x66\x0f\x7e\xf0"); p.equal(17); p.finish()
        struct.pack_into("<Q",p.data,start-0x2000,p.base+0x1000+len(p.code))
        p.emit(b"\x66\x0f\x7e\xf0\x50\xb8\x35\0\0\0\x66\x0f\x6e\xf0\x58\xc3")
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)
