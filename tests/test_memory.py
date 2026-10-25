import os
import struct
from pathlib import Path
import subprocess
import tempfile
import unittest

from kernel_fixture import Probe, reg, heap_probe, virtual_probe

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


class MemoryTests(unittest.TestCase):
    def run_program(self, program):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.exe"
            path.write_bytes(program.image())
            return subprocess.run([str(CLI), "run", str(path), "--root", str(Path(directory) / "drive")],
                                  capture_output=True, timeout=5)

    def test_heap_and_fixed_local_allocations_are_writable_and_freed(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                result = self.run_program(heap_probe(bits))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_virtual_allocation_query_protection_decommit_and_recommit(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                result = self.run_program(virtual_probe(bits))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_heaps_reject_wrong_owner_and_double_free(self):
        p = Probe(["HeapCreate", "HeapAlloc", "HeapFree", "HeapDestroy", "GetProcessHeap"])
        p.invoke("HeapCreate", [0, 0, 0])
        p.nonzero(); p.copy(6, 0)
        p.invoke("HeapAlloc", [reg(6), 8, 32])
        p.nonzero(); p.copy(3, 0)
        p.call("GetProcessHeap"); p.copy(7, 0)
        p.invoke("HeapFree", [reg(7), 0, reg(3)]); p.equal(0)
        p.invoke("HeapFree", [reg(6), 0, reg(3)]); p.equal(1)
        p.invoke("HeapFree", [reg(6), 0, reg(3)]); p.equal(0)
        p.invoke("HeapDestroy", [reg(6)]); p.equal(1)
        p.invoke("HeapAlloc", [reg(6), 0, 32]); p.equal(0)
        p.finish()
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reserved_memory_cannot_be_read_before_commit(self):
        p = Probe(["VirtualAlloc"])
        p.invoke("VirtualAlloc", [0, 4096, 0x2000, 4])
        p.emit(b"\x8b\x00")
        result = self.run_program(p)
        self.assertEqual(result.returncode, 65)
        self.assertIn(b"guest address", result.stderr)

    def test_readonly_memory_rejects_a_guest_write(self):
        p = Probe(["VirtualAlloc", "VirtualProtect"])
        old = p.blob(b"\0" * 4)
        p.invoke("VirtualAlloc", [0, 4096, 0x3000, 4]); p.copy(3, 0)
        p.invoke("VirtualProtect", [reg(3), 4096, 2, p.base + old])
        p.emit(b"\xc7\x03\x01\0\0\0")
        result = self.run_program(p)
        self.assertEqual(result.returncode, 65)
        self.assertIn(b"guest address", result.stderr)

    def test_non_executable_allocation_rejects_instruction_fetch(self):
        p = Probe(["VirtualAlloc"])
        p.invoke("VirtualAlloc", [0, 4096, 0x3000, 4])
        p.emit(b"\xc7\x00\xc3\0\0\0\xff\xe0")
        result = self.run_program(p)
        self.assertEqual(result.returncode, 65)
        self.assertIn(b"guest address", result.stderr)

    def test_virtual_free_requires_the_allocation_base_and_zero_release_size(self):
        p = Probe(["VirtualAlloc", "VirtualFree", "GetLastError"])
        p.invoke("VirtualAlloc", [0, 8192, 0x3000, 4]); p.copy(3, 0)
        p.invoke("VirtualFree", [reg(3), 4096, 0x8000]); p.equal(0)
        p.invoke("VirtualFree", [reg(3), 0, 0x8000]); p.equal(1)
        p.invoke("VirtualFree", [reg(3), 0, 0x8000]); p.equal(0)
        p.finish()
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_32_bit_virtual_alloc_cannot_cross_the_end_of_the_guest_address_space(self):
        p = Probe(["VirtualAlloc"], 32)
        p.invoke("VirtualAlloc", [0xfffff000, 8192, 0x3000, 4]); p.equal(0); p.finish()
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_absolute_accumulator_store_uses_the_guest_address_width(self):
        for bits in (32, 64):
            p = Probe([], bits)
            slot = p.blob(b"\0" * 8)
            value = 0x1122334455667788 if bits == 64 else 0x55667788
            p.mov(0, value)
            p.emit((b"\x48" if bits == 64 else b"") + b"\xa3" + struct.pack("<Q" if bits == 64 else "<I", p.base+slot))
            p.mov(3, p.base+slot)
            p.mov(0, value)
            p.require((b"\x48" if bits == 64 else b"") + b"\x3b\x03")
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_program(p)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_setcc_writes_only_the_selected_byte_and_preserves_flags(self):
        for bits in (32, 64):
            p = Probe([], bits)
            slot = p.blob(b"\xcc"*4)
            p.mov(0, 0x12340000)
            p.emit(b"\x83\xf8\x01\x0f\x95\xc0")
            p.equal(0x12340001)
            p.mov(3, p.base+slot)
            p.emit(b"\x0f\x94\x03") # Prior equal comparison left ZF set.
            p.require(b"\x81\x3b\x01\xcc\xcc\xcc")
            p.mov(0, 0); p.emit(b"\x83\xf8\x01\x0f\x92\xc0")
            p.equal(1); p.finish()
            with self.subTest(bits=bits):
                result = self.run_program(p)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_byte_mov_and_test_preserve_neighboring_register_and_memory_bytes(self):
        for bits in (32, 64):
            p = Probe([], bits)
            slot = p.blob(b"\xcc"*4)
            address = struct.pack("<Q" if bits == 64 else "<I", p.base+slot)
            p.mov(0, 0x12340041); p.emit(b"\xa2"+address)
            p.mov(0, 0x12340000); p.emit(b"\xa0"+address); p.equal(0x12340041)
            p.mov(3, p.base+slot); p.mov(1, 0x56780000)
            p.emit(b"\x8a\x0b\x84\xc9"); p.require(b"", 0x84)
            p.copy(0, 1); p.equal(0x56780041)
            p.emit(b"\x88\x4b\x01"); p.require(b"\x81\x3b\x41\x41\xcc\xcc")
            p.finish()
            with self.subTest(bits=bits):
                result = self.run_program(p)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_readonly_buffers_can_be_written_to_files_and_used_as_conversion_input(self):
        p = Probe(["VirtualAlloc", "VirtualProtect", "GetStdHandle", "WriteFile", "MultiByteToWideChar"])
        old, out, written = p.blob(b"\0"*4), p.blob(b"\0"*4), p.blob(b"\0"*4)
        p.invoke("VirtualAlloc", [0, 4096, 0x3000, 4]); p.copy(3, 0)
        p.emit(b"\xc7\x00\x41\0\0\0")
        p.invoke("VirtualProtect", [reg(3), 4096, 2, p.base+old]); p.equal(1)
        p.invoke("GetStdHandle", [0xfffffff5]); p.copy(6, 0)
        p.invoke("WriteFile", [reg(6), reg(3), 1, p.base+written, 0]); p.equal(1)
        p.invoke("MultiByteToWideChar", [65001, 8, reg(3), 1, p.base+out, 2]); p.equal(1)
        p.mov(0, p.base+out); p.require(b"\x83\x38\x41"); p.finish()
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"A")

    def test_zeroing_a_protected_heap_block_fails_without_crashing_the_host(self):
        p = Probe(["GetProcessHeap", "HeapAlloc", "HeapFree", "VirtualProtect"])
        old = p.blob(b"\0"*4)
        p.call("GetProcessHeap"); p.copy(6, 0)
        p.invoke("HeapAlloc", [reg(6), 0, 32]); p.copy(3, 0)
        p.invoke("VirtualProtect", [reg(3), 4096, 2, p.base+old]); p.equal(1)
        p.invoke("HeapFree", [reg(6), 0, reg(3)]); p.equal(1)
        p.invoke("HeapAlloc", [reg(6), 8, 32]); p.equal(0); p.finish()
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
