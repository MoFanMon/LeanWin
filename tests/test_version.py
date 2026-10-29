import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe, reg

ROOT=Path(__file__).resolve().parents[1]
CLI=Path(os.environ.get("LEANWIN_CLI", ROOT/"build/leanwin"))


def condition_probe(bits=64):
    p=Probe(["VerSetConditionMask","GetStdHandle","WriteFile"],bits)
    output=p.blob(b"\0"*8); written=p.blob(b"\0"*4)
    # Build from zero; native Windows also sets bit 63 in the returned mask.
    p.mov(2,0x11223344)
    p.invoke("VerSetConditionMask", [0,0,128,1] if bits==32 else [0,128,1])
    p.invoke("VerSetConditionMask", [reg(0),reg(2),2,3] if bits==32 else [reg(0),2,3])
    p.copy(3,0); p.copy(6,2)
    p.mov(0,p.base+output); p.emit(b"\x89\x18\x89\x70\x04" if bits==32 else b"\x48\x89\x18")
    p.invoke("GetStdHandle",[0xfffffff5])
    p.invoke("WriteFile",[reg(0),p.base+output,8,p.base+written,0])
    p.copy(0,3)
    p.equal(0x200018)
    if bits==32: p.copy(0,6); p.equal(0x80000000)
    else: p.mov(3,0x8000000000200018); p.require(b"\x48\x39\xd8")
    p.finish(); return p


def version_probe(bits=64):
    # Compare against the version actually returned by this environment, so
    # native Windows may use its manifest-dependent profile.
    p=Probe(["GetVersionExW","VerifyVersionInfoW","VerSetConditionMask","GetLastError"],bits)
    info=p.blob(struct.pack("<I",284)+b"\0"*280)
    p.invoke("GetVersionExW",[p.base+info]); p.equal(1)
    def compare(op):
        p.mov(0,0); p.mov(2,0)
        for field in (1,2,16,32):
            p.invoke("VerSetConditionMask",[reg(0),reg(2),field,op] if bits==32 else [reg(0),field,op])
        p.invoke("VerifyVersionInfoW",[p.base+info,0x33,reg(0),reg(2)] if bits==32 else [p.base+info,0x33,reg(0)])
    compare(1); p.equal(1)
    p.mov(0,p.base+info); p.emit(b"\xc7\x40\x04\xff\xff\xff\xff")
    compare(3); p.equal(0)
    p.call("GetLastError"); p.equal(1150); p.finish(); return p


class VersionTests(unittest.TestCase):
    def run_probe(self,p):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/"version.exe"; exe.write_bytes(p.image())
            return subprocess.run([str(CLI),"run",str(exe),"--root",str(Path(d)/"drive")],capture_output=True,timeout=5)

    def test_valid_condition_masks_use_both_windows_calling_conventions(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(condition_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_query_results_agree_with_equal_and_greater_equal_comparisons(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(version_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_version_queries_fill_the_guest_profile_and_validate_structure_size(self):
        for bits in (32,64):
            p=Probe(["GetVersion","GetVersionExW","GetLastError"],bits)
            p.call("GetVersion"); p.equal(0x4a65000a)
            for size in (276,284):
                info=p.blob(struct.pack("<I",size)+b"\xcc"*(size-4))
                p.invoke("GetVersionExW",[p.base+info]); p.equal(1)
                p.mov(0,p.base+info); p.require(b"\x83\x78\x04\x0a"); p.require(b"\x83\x78\x08\0")
                p.require(b"\x81\x78\x0c\x65\x4a\0\0")
                p.require(b"\x83\x78\x10\x02")
            bad=p.blob(struct.pack("<I",4))
            p.invoke("GetVersionExW",[p.base+bad]); p.equal(0)
            p.call("GetLastError"); p.equal(87); p.finish()
            with self.subTest(bits=bits):
                r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_version_comparison_uses_hierarchy_and_reports_unsatisfied_requirements(self):
        for bits in (32,64):
            p=Probe(["VerifyVersionInfoW","GetLastError"],bits)
            for major,minor,op,expected in [(6,3,3,1),(10,1,3,0),(11,0,3,0),(10,0,1,1),(10,0,2,0),(10,0,5,1)]:
                info=p.blob(struct.pack("<IIIII",284,major,minor,0,2)+b"\0"*264)
                # Compare major, minor and both service-pack fields together.
                mask=op|(op<<3)|(op<<12)|(op<<15)
                p.invoke("VerifyVersionInfoW",[p.base+info,0x33,mask,0] if bits==32 else [p.base+info,0x33,mask])
                p.equal(expected)
                if not expected: p.call("GetLastError"); p.equal(1150)
            p.finish()
            with self.subTest(bits=bits):
                r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)
