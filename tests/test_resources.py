import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from kernel_fixture import Probe

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


class ResourceProbe(Probe):
    def __init__(self, bits=64, named=False):
        super().__init__(["FindResourceW", "SizeofResource", "LoadResource", "LockResource", "GetLastError"], bits)
        self.named = named
        self.resource_root = 0x400
        for offset in (0, 24, 48):
            struct.pack_into("<HH", self.data, self.resource_root + offset + 12,
                             1 if named and offset != 48 else 0, 0 if named and offset != 48 else 1)
        for offset, key, target in [(16, 0x80000080 if named else 10, 0x80000018),
                                    (40, 0x80000090 if named else 7, 0x80000030), (64, 0x409, 72)]:
            struct.pack_into("<II", self.data, self.resource_root + offset, key, target)
        struct.pack_into("<IIII", self.data, self.resource_root + 72, 0x2500, 4, 0, 0)
        # Win32 resource APIs uppercase string keys before lookup. Resource
        # compilers store uppercase directory keys, unlike arbitrary PE strings.
        for offset, text in ((0x80, "TYPE"), (0x90, "SAMPLE")):
            struct.pack_into("<H", self.data, self.resource_root + offset, len(text))
            self.data[self.resource_root+offset+2:self.resource_root+offset+2+len(text)*2] = text.encode("utf-16le")
        self.data[0x500:0x504] = b"\x11\x22\x33\x44"

    def image(self):
        data = super().image()
        directories = 0x98 + (112 if self.bits == 64 else 96)
        struct.pack_into("<II", data, directories + 2 * 8, 0x2400, 0x104)
        return data


def resource_probe(bits=64, named=False):
    p = ResourceProbe(bits, named)
    name = p.base + p.wide("Sample") if named else 7
    kind = p.base + p.wide("TyPe") if named else 10
    p.invoke("FindResourceW", [0, name, kind]); p.nonzero(); p.copy(3, 0)
    p.invoke("SizeofResource", [0, (3,)]); p.equal(4)
    p.invoke("LoadResource", [0, (3,)]); p.nonzero()
    p.invoke("LockResource", [(0,)]); p.nonzero()
    p.require(b"\x81\x38\x11\x22\x33\x44")
    p.finish()
    return p


class ResourceTests(unittest.TestCase):
    def run_image(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resource.exe"
            path.write_bytes(data)
            return subprocess.run([str(CLI), "run", str(path), "--root", str(Path(directory) / "drive")],
                                  capture_output=True, timeout=5)

    def test_integer_and_unicode_named_resources_return_real_image_bytes(self):
        for bits in (32, 64):
            for named in (False, True):
                with self.subTest(bits=bits, named=named):
                    result = self.run_image(resource_probe(bits, named).image())
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_resource_type_and_name_report_windows_errors(self):
        for kind, name, expected in [(11, 7, 1813), (10, 8, 1814)]:
            p = ResourceProbe()
            p.invoke("FindResourceW", [0, name, kind]); p.equal(0)
            p.call("GetLastError"); p.equal(expected); p.finish()
            result = self.run_image(p.image())
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_resource_tree_offsets_are_checked_before_dereferencing(self):
        p = ResourceProbe()
        struct.pack_into("<I", p.data, p.resource_root + 20, 0xfffffff0)
        p.invoke("FindResourceW", [0, 7, 10]); p.equal(0)
        p.call("GetLastError"); p.nonzero(); p.finish()
        result = self.run_image(p.image())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_forged_resource_handles_are_rejected(self):
        p = ResourceProbe()
        p.invoke("SizeofResource", [0, 0xdead]); p.equal(0)
        p.invoke("LockResource", [0xdead]); p.equal(0)
        p.finish()
        result = self.run_image(p.image())
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
