"""PE probes shared by compatibility tests and native Windows comparisons."""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from build import Program, DATA


def reg(number):
    return (number,)


class Probe(Program):
    def __init__(self, names, bits=64):
        super().__init__([("KERNEL32.dll", name) for name in dict.fromkeys([*names, "ExitProcess"])], bits)
        self.failures = []
        self.prologue()

    def copy(self, target, source):
        if self.bits == 64:
            self.emit(bytes([0x48 | (4 if source >= 8 else 0) | (1 if target >= 8 else 0)]))
        self.emit(bytes([0x89, 0xc0 | ((source & 7) << 3) | (target & 7)]))

    def invoke(self, name, values):
        indexes = range(len(values) - 1, -1, -1) if self.bits == 32 else range(len(values))
        for i in indexes:
            value = values[i]
            if not isinstance(value, tuple):
                self.argument(i, value)
            elif self.bits == 32:
                self.emit(bytes([0x50 + value[0]]))
            elif i < 4:
                self.copy([1, 2, 8, 9][i], value[0])
            else:
                source = value[0]
                self.emit(bytes([0x48 | (4 if source >= 8 else 0), 0x89,
                                 0x44 | ((source & 7) << 3), 0x24, 32 + (i - 4) * 8]))
        self.call(name)

    def require(self, comparison, condition=0x85):
        self.emit(comparison + bytes([0x0f, condition]) + b"\0" * 4)
        self.failures.append(len(self.code) - 4)

    def equal(self, value):
        self.require(b"\x81\xf8" + struct.pack("<I", value & 0xffffffff))

    def nonzero(self):
        self.require((b"\x48" if self.bits == 64 else b"") + b"\x85\xc0", 0x84)

    def finish(self):
        self.exit(0)
        fail = len(self.code)
        self.exit(99)
        for offset in self.failures:
            struct.pack_into("<i", self.code, offset, fail - offset - 4)


def heap_probe(bits=64):
    p = Probe(["GetProcessHeap", "HeapAlloc", "HeapFree", "LocalAlloc", "LocalFree"], bits)
    p.call("GetProcessHeap")
    p.nonzero()
    p.copy(6, 0)
    p.invoke("HeapAlloc", [reg(6), 8, 64])
    p.nonzero()
    p.copy(3, 0)
    p.require(b"\x83\x38\0")
    p.emit(b"\xc7\x00\x7b\0\0\0")
    p.require(b"\x81\x38\x7b\0\0\0")
    p.invoke("HeapFree", [reg(6), 0, reg(3)])
    p.equal(1)
    p.invoke("LocalAlloc", [0x40, 37])
    p.nonzero()
    p.require(b"\x83\x38\0")
    p.invoke("LocalFree", [reg(0)])
    p.equal(0)
    p.finish()
    return p


def virtual_probe(bits=64):
    p = Probe(["VirtualAlloc", "VirtualQuery", "VirtualProtect", "VirtualFree"], bits)
    info, old = p.blob(b"\xcc" * 48), p.blob(b"\0" * 4)
    p.invoke("VirtualAlloc", [0, 8192, 0x3000, 4])
    p.nonzero()
    p.copy(3, 0)
    p.require(b"\x83\x38\0")
    p.emit(b"\xc7\x00\x4d\0\0\0")
    p.invoke("VirtualQuery", [reg(3), p.base + info, 48 if bits == 64 else 28])
    p.equal(48 if bits == 64 else 28)
    p.mov(0, p.base + info)
    p.require(b"\x81\x78" + bytes([32 if bits == 64 else 16]) + b"\0\x10\0\0")
    p.invoke("VirtualProtect", [reg(3), 4096, 2, p.base + old])
    p.equal(1)
    p.mov(0, p.base + old)
    p.require(b"\x83\x38\x04")
    p.copy(0, 3)
    p.require(b"\x81\x38\x4d\0\0\0")
    p.invoke("VirtualProtect", [reg(3), 4096, 4, p.base + old])
    p.equal(1)
    p.invoke("VirtualFree", [reg(3), 4096, 0x4000])
    p.equal(1)
    p.invoke("VirtualAlloc", [reg(3), 4096, 0x1000, 4])
    p.nonzero()
    p.require(b"\x83\x38\0")
    p.invoke("VirtualFree", [reg(3), 0, 0x8000])
    p.equal(1)
    p.finish()
    return p
