"""Windows PE probes for the bounded guest locale configuration."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe, reg

ROOT=Path(__file__).resolve().parents[1]
CLI=Path(os.environ.get("LEANWIN_CLI",ROOT/"build/leanwin"))


def locale_probe(bits=64):
    p=Probe(["SetThreadLocale","GetThreadLocale","IsValidLocale","GetUserDefaultLCID"],bits)
    p.call("GetUserDefaultLCID"); p.nonzero(); p.copy(6,0)
    for locale in (0x409,0x7f):
        p.invoke("IsValidLocale",[locale,2]); p.nonzero()
        p.invoke("SetThreadLocale",[locale]); p.nonzero()
        p.call("GetThreadLocale"); p.equal(locale)
    p.invoke("SetThreadLocale",[0x400]); p.nonzero()
    p.call("GetThreadLocale"); p.require((b"\x48" if bits==64 else b"")+b"\x39\xf0")
    p.finish(); return p


def locale_thread_probe(bits=64):
    p=Probe(["GetUserDefaultLCID","SetThreadLocale","GetThreadLocale","CreateThread","WaitForSingleObject","GetExitCodeThread"],bits)
    start,code=p.blob(b"\0"*8),p.blob(b"\0"*4)
    p.call("GetUserDefaultLCID"); p.copy(7,0)
    p.invoke("SetThreadLocale",[0x7f]); p.nonzero()
    p.mov(0,p.base+start); p.emit((b"\x48" if bits==64 else b"")+b"\x8b\x30")
    p.invoke("CreateThread",[0,0,reg(6),0,0,0]); p.nonzero(); p.copy(3,0)
    p.invoke("WaitForSingleObject",[reg(3),0xffffffff]); p.equal(0)
    p.invoke("GetExitCodeThread",[reg(3),p.base+code]); p.nonzero()
    p.mov(0,p.base+code); p.require(b"\x39\x38")
    p.call("GetThreadLocale"); p.equal(0x7f)
    p.invoke("SetThreadLocale",[reg(7)]); p.nonzero(); p.finish()
    struct.pack_into("<Q" if bits==64 else "<I",p.data,start-0x2000,p.base+0x1000+len(p.code))
    p.prologue(); p.call("GetThreadLocale")
    p.emit(b"\x48\x83\xc4\x68\xc3" if bits==64 else b"\xc2\x04\0")
    return p


def locale_info_probe(bits=64):
    p=Probe(["GetLocaleInfoW"],bits); output=p.blob(b"\xcc"*64)
    p.invoke("GetLocaleInfoW",[0x409,0x5c,0,0]); p.equal(6)
    p.invoke("GetLocaleInfoW",[0x409,0x5c,p.base+output,32]); p.equal(6)
    p.mov(0,p.base+output); p.require(b"\x81\x38\x65\0\x6e\0")
    p.require(b"\x81\x78\x04\x2d\0\x55\0")
    p.invoke("GetLocaleInfoW",[0x804,0x20000001,p.base+output,2]); p.equal(2)
    p.mov(0,p.base+output); p.require(b"\x81\x38\x04\x08\0\0")
    p.invoke("GetLocaleInfoW",[0x804,0x0e,p.base+output,32]); p.equal(2)
    p.mov(0,p.base+output); p.require(b"\x81\x38\x2e\0\0\0")
    for locale,number in ((0x409,1252),(0x804,936)):
        p.invoke("GetLocaleInfoW",[locale,0xa0001004,p.base+output,2]); p.equal(2)
        p.mov(0,p.base+output); p.require(b"\x81\x38"+struct.pack("<I",number))
    p.finish(); return p


def ordinal_probe(bits=64):
    p=Probe(["CompareStringOrdinal","LCMapStringW"],bits)
    left,right=p.wide("AbC"),p.wide("aBc"); output=p.blob(b"\xcc"*16)
    p.invoke("CompareStringOrdinal",[p.base+left,-1,p.base+right,-1,1]); p.equal(2)
    p.invoke("CompareStringOrdinal",[p.base+left,-1,p.base+right,-1,0]); p.equal(1)
    p.invoke("LCMapStringW",[0x409,0x100,p.base+left,-1,0,0]); p.equal(4)
    p.invoke("LCMapStringW",[0x409,0x100,p.base+left,-1,p.base+output,8]); p.equal(4)
    p.invoke("CompareStringOrdinal",[p.base+output,-1,p.base+right,-1,1]); p.equal(2)
    p.mov(0,p.base+output); p.require(b"\x81\x38\x61\0\x62\0")
    p.finish(); return p


def system_info_probe(bits=64):
    p=Probe(["GetSystemInfo"],bits); output=p.blob(b"\xcc"*64)
    p.invoke("GetSystemInfo",[p.base+output]); p.mov(0,p.base+output)
    p.require(b"\x66\x83\x38"+bytes([9 if bits==64 else 0]))
    p.require(b"\x81\x78\x04\0\x10\0\0")
    p.require(b"\x81\x78"+bytes([40 if bits==64 else 28])+b"\0\0\x01\0")
    p.require(b"\x83\x78"+bytes([32 if bits==64 else 20])+b"\0",0x84)
    p.finish(); return p


class LocaleTests(unittest.TestCase):
    def run_probe(self,p):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/"locale.exe"; exe.write_bytes(p.image())
            return subprocess.run([str(CLI),"run",str(exe),"--root",str(Path(d)/"drive")],capture_output=True,timeout=5)

    def test_thread_locale_round_trip_and_user_default_alias(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(locale_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_new_thread_uses_user_default_and_keeps_parent_locale_isolated(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(locale_thread_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_invalid_locale_does_not_change_current_thread_state(self):
        p=Probe(["SetThreadLocale","GetThreadLocale","GetLastError","IsValidLocale"])
        p.invoke("SetThreadLocale",[0x804]); p.nonzero()
        p.invoke("SetThreadLocale",[0xffffffff]); p.equal(0)
        p.call("GetLastError"); p.equal(87)
        p.call("GetThreadLocale"); p.equal(0x804)
        p.invoke("IsValidLocale",[0xffffffff,2]); p.equal(0); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_default_locale_and_language_queries_describe_one_guest_profile(self):
        p=Probe(["GetUserDefaultLCID","GetSystemDefaultLCID","GetUserDefaultLangID","GetSystemDefaultLangID","GetUserDefaultUILanguage","GetSystemDefaultUILanguage"])
        for name in ("GetUserDefaultLCID","GetSystemDefaultLCID","GetUserDefaultLangID","GetSystemDefaultLangID","GetUserDefaultUILanguage","GetSystemDefaultUILanguage"):
            p.call(name); p.equal(0x409)
        p.finish(); r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_locale_info_size_string_and_numeric_outputs_use_windows_layout(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(locale_info_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_ordinal_comparison_and_ascii_case_mapping(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(ordinal_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_small_locale_buffer_fails_without_partial_output(self):
        p=Probe(["GetLocaleInfoW","GetLastError"]); output=p.blob(b"\xcc"*16)
        p.invoke("GetLocaleInfoW",[0x409,0x5c,p.base+output,2]); p.equal(0)
        p.call("GetLastError"); p.equal(122)
        p.mov(0,p.base+output); p.require(b"\x81\x38\xcc\xcc\xcc\xcc"); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_ordinal_explicit_lengths_keep_embedded_null_and_non_ascii_units(self):
        p=Probe(["CompareStringOrdinal"])
        a,b=p.blob("中\0a".encode("utf-16le")),p.blob("中\0b".encode("utf-16le"))
        p.invoke("CompareStringOrdinal",[p.base+a,3,p.base+b,3,0]); p.equal(1)
        p.invoke("CompareStringOrdinal",[p.base+a,-1,p.base+b,-1,0]); p.equal(2)
        p.invoke("CompareStringOrdinal",[p.base+a,0,p.base+b,0,0]); p.equal(2); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_unimplemented_case_mapping_and_flags_return_errors(self):
        p=Probe(["LCMapStringW","CompareStringOrdinal","GetLastError"])
        source=p.wide("é"); output=p.blob(b"\xcc"*16)
        p.invoke("LCMapStringW",[0x409,0x100,p.base+source,-1,p.base+output,8]); p.equal(0)
        p.call("GetLastError"); p.equal(50)
        p.invoke("CompareStringOrdinal",[p.base+source,-1,p.base+source,-1,1]); p.equal(0)
        p.call("GetLastError"); p.equal(50)
        p.invoke("LCMapStringW",[0x409,0x300,p.base+source,-1,p.base+output,8]); p.equal(0)
        p.call("GetLastError"); p.equal(1004); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_system_info_describes_guest_pages_and_processor_architecture(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(system_info_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_mapping_allows_in_place_ascii_and_preserves_short_buffers(self):
        p=Probe(["LCMapStringW","GetLastError"]); source=p.wide("AbC"); out=p.blob(b"\xcc"*16)
        p.invoke("LCMapStringW",[0x409,0x200,p.base+source,-1,p.base+source,4]); p.equal(4)
        p.mov(0,p.base+source); p.require(b"\x81\x38\x41\0\x42\0")
        p.invoke("LCMapStringW",[0x409,0x100,p.base+source,-1,p.base+out,2]); p.equal(0)
        p.call("GetLastError"); p.equal(122)
        p.mov(0,p.base+out); p.require(b"\x81\x38\xcc\xcc\xcc\xcc"); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_locale_setting_is_visible_through_the_current_teb(self):
        for bits in (32,64):
            p=Probe(["SetThreadLocale","GetThreadLocale"],bits)
            p.invoke("SetThreadLocale",[0x804]); p.nonzero()
            p.emit(b"\x65\x8b\x04\x25\x08\x01\0\0" if bits==64 else b"\x64\xa1\xc4\0\0\0")
            p.equal(0x804); p.finish()
            with self.subTest(bits=bits):
                r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_x64_dword_locale_parameters_ignore_unspecified_register_high_bits(self):
        p=Probe(["IsValidLocale","LCMapStringW","CompareStringOrdinal"])
        source=p.wide("ab"); target=p.wide("AB"); out=p.blob(b"\0"*8)
        p.invoke("IsValidLocale",[0x100000409,0x100000002]); p.nonzero()
        p.invoke("LCMapStringW",[0x409,0x100000200,p.base+source,-1,p.base+out,4]); p.equal(3)
        p.invoke("CompareStringOrdinal",[p.base+out,-1,p.base+target,-1,0x100000001]); p.equal(2)
        p.finish(); r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)
