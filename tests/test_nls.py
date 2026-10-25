"""Check Windows string-call results through real PE programs, on both ABIs."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
from build import Program

CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))
NLS_PROBE_EXPECTED = (b"\x01\0\0\0\x04\0\0\0?\0" + b"\0" * 12 + b"\xfd\xff\xe9\xfd\0\0" +
                      b"\x04\0\0\0\x2d\x4e\x3d\xd8\x0b\xdc\0\0" +
                      b"\x08\0\0\0\xe4\xb8\xad\xf0\x9f\x90\x8b\0")


class NLSProgram(Program):
    def __init__(self, bits=64):
        names = ("GetACP", "GetCPInfo", "GetCPInfoExW", "MultiByteToWideChar",
                 "WideCharToMultiByte", "GetLastError", "GetStdHandle", "WriteFile", "ExitProcess")
        super().__init__([("KERNEL32.dll", name) for name in names], bits)
        self.prologue()

    def output(self, address, length):
        written = self.blob(b"\0" * 4)
        self.invoke("GetStdHandle", [-11])
        self.handle_call("WriteFile", [self.base + address, length, self.base + written, 0], register=0)

    def result(self):
        address = self.blob(b"\0" * 4)
        self.mov(3, self.base + address)
        self.emit(b"\x89\x03")
        self.output(address, 4)

    def error(self):
        self.call("GetLastError")
        self.result()


def nls_probe(bits):
    """An explicit UTF-8 conversion with identical expectations on Windows."""
    p = NLSProgram(bits)
    info = p.blob(b"\xcc" * 544)
    p.invoke("GetCPInfoExW", [65001, 0, p.base + info])
    p.result()
    p.output(info, 24)
    encoded = p.blob(b"\xe4\xb8\xad\xf0\x9f\x90\x8b\0")
    wide = p.blob(b"\xcc" * 16)
    restored = p.blob(b"\xcc" * 16)
    p.invoke("MultiByteToWideChar", [65001, 8, p.base + encoded, -1, p.base + wide, 8])
    p.result()
    p.output(wide, 8)
    p.invoke("WideCharToMultiByte", [65001, 128, p.base + wide, -1, p.base + restored, 16, 0, 0])
    p.result()
    p.output(restored, 8)
    p.exit(0)
    return p


class NLSTests(unittest.TestCase):
    def run_program(self, p):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "nls.exe"
            exe.write_bytes(p.image())
            result = subprocess.run([str(CLI), "run", str(exe), "--root", str(Path(directory) / "drive")],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

    def test_acp_describes_the_utf8_guest_profile(self):
        for bits in (32, 64):
            p = NLSProgram(bits)
            p.call("GetACP")
            p.result()
            encoded, output = p.blob(b"\xe4\xb8\xad"), p.blob(b"\xcc" * 2)
            p.call("GetACP")
            p.handle_call("MultiByteToWideChar", [8, p.base + encoded, 3, p.base + output, 1], register=0)
            p.result()
            p.output(output, 2)
            p.exit(0)
            with self.subTest(bits=bits):
                self.assertEqual(self.run_program(p), b"\xe9\xfd\0\0\x01\0\0\0\x2d\x4e")

    def test_cpinfo_and_extended_cpinfo_write_windows_layout(self):
        for bits in (32, 64):
            p = NLSProgram(bits)
            info, extended = p.blob(b"\xcc" * 20), p.blob(b"\xcc" * 544)
            p.invoke("GetCPInfo", [0, p.base + info])
            p.result()
            p.output(info, 18)
            p.invoke("GetCPInfoExW", [65001, 0, p.base + extended])
            p.result()
            p.output(extended, 24)
            p.exit(0)
            expected_info = b"\x04\0\0\0?\0" + b"\0" * 12
            with self.subTest(bits=bits):
                output = self.run_program(p)
                self.assertEqual(output[:22], b"\x01\0\0\0" + expected_info)
                self.assertEqual(output[22:44], b"\x01\0\0\0" + expected_info)
                self.assertEqual(output[46:50], b"\xe9\xfd\0\0")  # CodePage at offset 20.

    def test_utf8_utf16_round_trip_preserves_chinese_emoji_and_terminator(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                output = self.run_program(nls_probe(bits))
                self.assertEqual(output, NLS_PROBE_EXPECTED)

    def test_multibyte_size_query_counts_utf16_units(self):
        p = NLSProgram()
        source = p.blob(b"\xf0\x9f\x90\x8b\0")
        p.invoke("MultiByteToWideChar", [65001, 8, p.base + source, -1, 0, 0])
        p.result()
        p.exit(0)
        self.assertEqual(self.run_program(p), b"\x03\0\0\0")

    def test_explicit_lengths_preserve_embedded_nulls_without_adding_terminator(self):
        for bits in (32, 64):
            p = NLSProgram(bits)
            source, dest = p.blob(b"a\0b"), p.blob(b"\xcc" * 8)
            p.invoke("MultiByteToWideChar", [0, 0, p.base + source, 3, p.base + dest, 3])
            p.result()
            p.output(dest, 8)
            p.exit(0)
            with self.subTest(bits=bits):
                self.assertEqual(self.run_program(p), b"\x03\0\0\0a\0\0\0b\0\xcc\xcc")

    def test_invalid_utf8_strict_mode_fails_with_windows_translation_error(self):
        for source in (b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"):
            p = NLSProgram()
            address = p.blob(source)
            p.invoke("MultiByteToWideChar", [65001, 8, p.base + address, len(source), 0, 0])
            p.result()
            p.error()
            p.exit(0)
            with self.subTest(source=source):
                self.assertEqual(self.run_program(p), b"\0" * 4 + struct.pack("<I", 1113))

    def test_invalid_utf8_replacement_uses_unicode_maximal_subparts(self):
        cases = [(b"\xc0\x80", b"\xfd\xff\xfd\xff"),
                 (b"\xe2\x82", b"\xfd\xff"),
                 (b"\xe1\x80A", b"\xfd\xffA\0"),
                 (b"\xed\xa0\x80", b"\xfd\xff" * 3)]
        for source, expected in cases:
            p = NLSProgram()
            address, dest = p.blob(source), p.blob(b"\xcc" * 16)
            p.invoke("MultiByteToWideChar", [65001, 0, p.base + address, len(source), p.base + dest, 8])
            p.output(dest, len(expected))
            p.exit(0)
            with self.subTest(source=source):
                self.assertEqual(self.run_program(p), expected)

    def test_unpaired_utf16_surrogates_are_rejected_or_replaced(self):
        for bits in (32, 64):
            p = NLSProgram(bits)
            source, dest = p.blob(b"\x00\xd8A\0"), p.blob(b"\xcc" * 8)
            p.invoke("WideCharToMultiByte", [65001, 128, p.base + source, 2, p.base + dest, 8, 0, 0])
            p.result()
            p.error()
            p.invoke("WideCharToMultiByte", [65001, 0, p.base + source, 2, p.base + dest, 8, 0, 0])
            p.result()
            p.output(dest, 4)
            p.exit(0)
            with self.subTest(bits=bits):
                self.assertEqual(self.run_program(p), b"\0" * 4 + struct.pack("<I", 1113) +
                                 b"\x04\0\0\0\xef\xbf\xbdA")

    def test_small_conversion_buffers_fail_without_partial_writes(self):
        for api in ("MultiByteToWideChar", "WideCharToMultiByte"):
            p = NLSProgram()
            source = p.blob(b"\xe4\xb8\xad" if api.startswith("Multi") else b"\x2d\x4e")
            dest = p.blob(b"\xcc" * 8)
            args = [65001, 0, p.base + source, 3 if api.startswith("Multi") else 1, p.base + dest,
                    0 if api.startswith("Multi") else 2]
            # MultiByte query is valid; a two-code-unit result in capacity one is insufficient.
            if api.startswith("Multi"):
                p.data[source - 0x2000:source - 0x2000 + 3] = b"abc"
                args[5] = 1
            else:
                args += [0, 0]
            p.invoke(api, args)
            p.result()
            p.error()
            p.output(dest, 8)
            p.exit(0)
            with self.subTest(api=api):
                self.assertEqual(self.run_program(p), b"\0" * 4 + struct.pack("<I", 122) + b"\xcc" * 8)

    def test_unsupported_pages_flags_and_utf8_default_character_parameters_fail(self):
        cases = [("GetCPInfo", [936, "dest"], 87),
                 ("GetCPInfoExW", [65001, 1, "dest"], 1004),
                 ("MultiByteToWideChar", [65001, 1, "source", 1, "dest", 8], 1004),
                 ("MultiByteToWideChar", [65001, 0, "source", 0, "dest", 8], 87),
                 ("WideCharToMultiByte", [65001, 0, "source", 1, "dest", 8, "source", 0], 87),
                 ("WideCharToMultiByte", [65001, 0, "source", 1, "dest", 8, 0, "used"], 87)]
        for bits in (32, 64):
            for api, args, error in cases:
                p = NLSProgram(bits)
                values = {"source": p.base + p.blob(b"A\0"), "dest": p.base + p.blob(b"\0" * 544),
                          "used": p.base + p.blob(b"\0" * 4)}
                p.invoke(api, [values.get(value, value) for value in args])
                p.result()
                p.error()
                p.exit(0)
                with self.subTest(bits=bits, api=api, args=args):
                    self.assertEqual(self.run_program(p), b"\0" * 4 + struct.pack("<I", error))


if __name__ == "__main__":
    unittest.main()
