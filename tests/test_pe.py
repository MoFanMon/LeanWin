"""Exercise the real executable against independently constructed PE files."""
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "build" / "leanwin"


def pe_fixture(bits=64, *, delayed=False, managed=False):
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if bits == 64 else 224
    struct.pack_into("<HHIIIHH", data, 0x84,
                     0x8664 if bits == 64 else 0x14c, 1, 0, 0, 0,
                     optional_size, 0x22 if bits == 64 else 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20b if bits == 64 else 0x10b)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q" if bits == 64 else "<I", data,
                     optional + (24 if bits == 64 else 28), 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, optional + 68, 2)
    struct.pack_into("<I", data, optional + (108 if bits == 64 else 92), 16)
    directories = optional + (112 if bits == 64 else 96)
    struct.pack_into("<II", data, directories + 8, 0x1000, 40)
    section = optional + optional_size
    data[section:section + 8] = b".idata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)
    struct.pack_into("<IIIII", data, 0x200, 0x1100, 0, 0, 0x1080, 0x1120)
    data[0x280:0x28d] = b"KERNEL32.dll\0"
    kind = "<QQQ" if bits == 64 else "<III"
    ordinal = (1 << (bits - 1)) | 7
    struct.pack_into(kind, data, 0x300, 0x1150, ordinal, 0)
    struct.pack_into("<H", data, 0x350, 0)
    data[0x352:0x35e] = b"ExitProcess\0"
    if delayed:
        struct.pack_into("<II", data, directories + 13 * 8, 0x1200, 64)
        struct.pack_into("<IIIIIIII", data, 0x400,
                         1, 0x1280, 0, 0x12b0, 0x12a0, 0, 0, 0)
        data[0x480:0x48b] = b"USER32.dll\0"
        struct.pack_into("<QQ" if bits == 64 else "<II", data, 0x4a0, 0x12d0, 0)
        data[0x4d2:0x4de] = b"MessageBoxW\0"
    if managed:
        struct.pack_into("<II", data, directories + 14 * 8, 0x1300, 72)
    return data


class InspectionTests(unittest.TestCase):
    def inspect(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example with spaces.exe"
            path.write_bytes(data)
            return subprocess.run([str(CLI), "inspect", str(path)],
                                  capture_output=True, text=True)

    def test_pe32_imports_and_ordinals(self):
        result = self.inspect(pe_fixture(32))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["architecture"], "x86")
        self.assertEqual(report["format"], "PE32")
        self.assertEqual(report["subsystem"], "windows-gui")
        self.assertEqual(report["imports"], [{"dll": "KERNEL32.dll",
                          "delayed": False, "symbols": ["ExitProcess", "#7"]}])

    def test_pe64_delayed_imports_and_managed_marker(self):
        result = self.inspect(pe_fixture(delayed=True, managed=True))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["architecture"], "x86_64")
        self.assertEqual(report["format"], "PE32+")
        self.assertTrue(report["managed"])
        self.assertEqual(report["imports"][1], {"dll": "USER32.dll",
                          "delayed": True, "symbols": ["MessageBoxW"]})

    def test_arm64_is_identified_without_claiming_x86_translation(self):
        data = pe_fixture()
        struct.pack_into("<H", data, 0x84, 0xaa64)
        result = self.inspect(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["architecture"], "arm64")

    def test_invalid_and_truncated_files_are_rejected(self):
        for data in (b"", b"hello", b"MZ" + b"\0" * 90, pe_fixture()[:0x130]):
            with self.subTest(length=len(data)):
                result = self.inspect(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)

    def test_import_name_cannot_read_virtual_zero_fill_as_file_data(self):
        data = pe_fixture()
        section = 0x98 + 240
        struct.pack_into("<I", data, section + 8, 0x1000)
        struct.pack_into("<I", data, 0x200 + 12, 0x1500)
        result = self.inspect(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RVA", result.stderr)

    def test_out_of_file_section_is_rejected(self):
        data = pe_fixture()
        struct.pack_into("<I", data, 0x98 + 240 + 20, 0xfffffff0)
        result = self.inspect(data)
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_extension_does_not_prevent_pe_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "program.bin"
            path.write_bytes(pe_fixture())
            result = subprocess.run([str(CLI), "inspect", str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
