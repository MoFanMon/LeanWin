"""Hand-built PE tests for guest x87 state, without using host FP registers."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe, reg

ROOT=Path(__file__).resolve().parents[1]
CLI=Path(os.environ.get("LEANWIN_CLI",ROOT/"build/leanwin"))


def fpu_control_probe(bits=64):
    p=Probe([],bits); output=p.blob(b"\xcc"*8)
    p.emit(b"\xdb\xe3\x9b") # FNINIT, FWAIT.
    p.mov(0,p.base+output); p.emit(b"\xd9\x38") # FNSTCW [eax/rax].
    p.require(b"\x81\x38\x7f\x03\xcc\xcc")
    for control in (0x077f,0x0b7f,0x1332):
        source=p.blob(struct.pack("<H",control))
        p.mov(0,p.base+source); p.emit(b"\xd9\x28\x9b")
        p.mov(0,p.base+output); p.emit(b"\xd9\x38\x0f\xb7\x00")
        p.emit(b"\x25\x3f\x1f\0\0"); p.equal(control&0x1f3f)
    p.emit(b"\xdb\xe2") # FNCLEX.
    p.mov(0,0x12340000); p.emit(b"\xdf\xe0"); p.equal(0x12340000)
    p.emit(b"\x9b\xdb\xe3") # FINIT form restores the default control word.
    p.mov(0,p.base+output); p.emit(b"\xd9\x38\xdd\x78\x02")
    p.require(b"\x81\x38\x7f\x03\0\0")
    p.finish(); return p


def fpu_thread_probe(bits=64):
    p=Probe(["CreateThread","WaitForSingleObject","GetExitCodeThread"],bits)
    start,code=p.blob(b"\0"*8),p.blob(b"\0"*4)
    parent,child,output=p.blob(b"\x7f\x07"),p.blob(b"\x7f\x0b"),p.blob(b"\0"*4)
    p.emit(b"\xdb\xe3"); p.mov(0,p.base+parent); p.emit(b"\xd9\x28")
    p.mov(0,p.base+start); p.emit((b"\x48" if bits==64 else b"")+b"\x8b\x38")
    p.invoke("CreateThread",[0,0,reg(7),0,0,0]); p.copy(3,0)
    p.invoke("WaitForSingleObject",[reg(3),0xffffffff]); p.equal(0)
    p.invoke("GetExitCodeThread",[reg(3),p.base+code]); p.nonzero()
    p.mov(0,p.base+code); p.require(b"\x81\x38\x7f\x0b\0\0")
    p.mov(0,p.base+output); p.emit(b"\xd9\x38"); p.require(b"\x81\x38\x7f\x07\0\0")
    p.finish()
    struct.pack_into("<Q" if bits==64 else "<I",p.data,start-0x2000,p.base+0x1000+len(p.code))
    p.emit(b"\xdb\xe3"); p.mov(0,p.base+child); p.emit(b"\xd9\x28")
    p.mov(0,p.base+output); p.emit(b"\xd9\x38\x0f\xb7\x00")
    p.emit(b"\xc3" if bits==64 else b"\xc2\x04\0")
    return p


def fpu_environment_probe(bits=64,short=False):
    p=Probe([],bits); size=14 if short else 28; prefix=b"\x66" if short else b""
    env=bytearray(size)
    struct.pack_into("<H",env,0,0x077f)
    struct.pack_into("<H",env,2 if short else 4,0x3f43)
    struct.pack_into("<H",env,4 if short else 8,0xffff)
    source,output=p.blob(env),p.blob(b"\xcc"*32)
    p.emit(b"\xdb\xe3"); p.mov(0,p.base+source); p.emit(prefix+b"\xd9\x20") # FLDENV.
    p.emit(b"\xdb\xe2\xdf\xe0"); p.emit(b"\x25\xff\xff\0\0"); p.equal(0x3f00)
    p.mov(0,p.base+output); p.emit(prefix+b"\xd9\x30") # FNSTENV.
    p.emit(b"\x0f\xb7\x00"); p.equal(0x077f)
    p.mov(0,p.base+output+(2 if short else 4)); p.emit(b"\x0f\xb7\x00"); p.equal(0x3f00)
    p.mov(0,p.base+output+(4 if short else 8)); p.emit(b"\x0f\xb7\x00"); p.equal(0xffff)
    # Saving the environment stores the old CW, then masks exceptions in the FPU.
    word=p.blob(b"\x72\x13")
    p.emit(b"\xdb\xe3"); p.mov(0,p.base+word); p.emit(b"\xd9\x28")
    p.mov(0,p.base+output); p.emit(prefix+b"\xd9\x30\x0f\xb7\x00\x25\x3f\x1f\0\0"); p.equal(0x1332)
    p.mov(0,p.base+output); p.emit(b"\xd9\x38\x0f\xb7\x00\x25\x3f\x1f\0\0"); p.equal(0x133f)
    p.finish(); return p


class FPUTests(unittest.TestCase):
    def run_probe(self,p):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/"fpu.exe"; exe.write_bytes(p.image())
            return subprocess.run([str(CLI),"run",str(exe),"--root",str(Path(d)/"drive")],capture_output=True,timeout=5)

    def test_init_control_word_status_and_wait_match_x87_state(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(fpu_control_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_threads_keep_independent_control_words(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(fpu_thread_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_control_word_store_checks_guest_page_protection(self):
        p=Probe(["VirtualAlloc"])
        p.invoke("VirtualAlloc",[0,4096,0x3000,2]); p.emit(b"\xdb\xe3\xd9\x38"); p.exit(0)
        r=self.run_probe(p); self.assertEqual(r.returncode,65); self.assertIn(b"protection",r.stderr)

    def test_environment_restore_exception_clear_and_save_side_effects(self):
        for bits in (32,64):
            for short in (False,True):
                with self.subTest(bits=bits,short=short):
                    r=self.run_probe(fpu_environment_probe(bits,short)); self.assertEqual(r.returncode,0,r.stderr)

    def test_wait_stops_on_pending_unmasked_exception_and_clear_allows_progress(self):
        for clear in (False,True):
            p=Probe([]); env=bytearray(28)
            struct.pack_into("<H",env,0,0x037e); struct.pack_into("<H",env,4,1); struct.pack_into("<H",env,8,0xffff)
            source=p.blob(env)
            p.emit(b"\xdb\xe3"); p.mov(0,p.base+source); p.emit(b"\xd9\x20")
            if clear: p.emit(b"\xdb\xe2")
            p.emit(b"\x9b"); p.exit(0)
            with self.subTest(clear=clear):
                r=self.run_probe(p); self.assertEqual(r.returncode,0 if clear else 65,r.stderr)
                if not clear: self.assertIn(b"x87 exception",r.stderr)

    def test_environment_load_checks_all_bytes_before_restoring_state(self):
        p=Probe(["VirtualAlloc"])
        p.invoke("VirtualAlloc",[0,4096,0x3000,4]); p.emit(b"\x48\x05\xf0\x0f\0\0\xd9\x20"); p.exit(0)
        r=self.run_probe(p); self.assertEqual(r.returncode,65); self.assertIn(b"guest address",r.stderr)

    def test_no_wait_init_clears_pending_exception_without_raising_it(self):
        p=Probe([]); env=bytearray(28)
        struct.pack_into("<H",env,0,0x037e); struct.pack_into("<H",env,4,1); struct.pack_into("<H",env,8,0xffff)
        source=p.blob(env)
        p.emit(b"\xdb\xe3"); p.mov(0,p.base+source); p.emit(b"\xd9\x20\xdb\xe3\x9b\xdf\xe0")
        p.emit(b"\x25\xff\xff\0\0"); p.equal(0); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)
