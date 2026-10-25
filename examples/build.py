"""Build tiny, real PE executables for the explicitly supported interface subset.

These examples contain hand-assembled x86 instructions, not recompiled Mac apps.
They can also be examined or executed on Windows. No Windows SDK is required.
"""
from pathlib import Path
import struct

BASE64 = 0x140000000
TEXT = 0x1000
DATA = 0x2000


class Program:
    def __init__(self, imports, bits=64, gui=False):
        self.bits, self.gui = bits, gui
        self.base = BASE64 if bits == 64 else 0x400000
        self.code = bytearray()
        self.data = bytearray(4096)
        self.cursor = 0x800
        self.iat = {}
        groups = {}
        for dll, name in imports:
            groups.setdefault(dll, []).append(name)
        cursor = 0x80
        for row, (dll, names) in enumerate(groups.items()):
            dll_rva = DATA + cursor
            raw = dll.encode() + b"\0"
            self.data[cursor:cursor + len(raw)] = raw
            cursor = (cursor + len(raw) + 7) & ~7
            table = cursor
            word = bits // 8
            cursor += (len(names) + 1) * word
            struct.pack_into("<IIIII", self.data, row * 20,
                             DATA + table, 0, 0, dll_rva, DATA + table)
            for index, name in enumerate(names):
                raw = b"\0\0" + name.encode() + b"\0"
                struct.pack_into("<Q" if bits == 64 else "<I", self.data,
                                 table + index * word, DATA + cursor)
                self.iat[name] = DATA + table + index * word
                self.data[cursor:cursor + len(raw)] = raw
                cursor = (cursor + len(raw) + 1) & ~1
        self.import_size = (len(groups) + 1) * 20

    def emit(self, data):
        self.code.extend(data)

    def blob(self, data):
        offset = self.cursor
        self.data[offset:offset + len(data)] = data
        self.cursor = (offset + len(data) + 7) & ~7
        assert self.cursor <= len(self.data)
        return DATA + offset

    def wide(self, text):
        return self.blob(text.encode("utf-16le") + b"\0\0")

    def call(self, name):
        target = self.iat[name]
        operand = target - (TEXT + len(self.code) + 6) if self.bits == 64 else self.base + target
        self.emit(b"\xff\x15" + struct.pack("<I", operand & 0xffffffff))

    def mov(self, register, value):
        if self.bits == 32:
            self.emit(bytes([0xb8 + register]) + struct.pack("<I", value & 0xffffffff))
        else:
            self.emit(bytes([0x48 | (register >> 3), 0xb8 + (register & 7)]) + struct.pack("<Q", value & 0xffffffffffffffff))

    def argument(self, index, value):
        if self.bits == 32:
            self.emit(b"\x68" + struct.pack("<I", value & 0xffffffff))
        elif index < 4:
            self.mov([1, 2, 8, 9][index], value)
        else:
            displacement = bytes([32 + (index - 4) * 8])
            if -(1 << 31) <= value < (1 << 31):
                self.emit(b"\x48\xc7\x44\x24" + displacement + struct.pack("<i", value))
            else:
                self.mov(0, value)
                self.emit(b"\x48\x89\x44\x24" + displacement)

    def invoke(self, name, values):
        indexes = range(len(values) - 1, -1, -1) if self.bits == 32 else range(len(values))
        for index in indexes:
            self.argument(index, values[index])
        self.call(name)

    def prologue(self):
        if self.bits == 64:
            self.emit(b"\x48\x83\xec\x68")

    def exit(self, code):
        self.invoke("ExitProcess", [code])

    def save_handle(self):
        self.emit(b"\x48\x89\xc3" if self.bits == 64 else b"\x89\xc3")

    def handle_call(self, name, values, register=3):
        if self.bits == 32:
            for index in range(len(values), 0, -1):
                self.argument(index, values[index - 1])
            self.emit(bytes([0x50 + register]))
        else:
            self.emit(b"\x48\x89\xd9" if register == 3 else b"\x48\x89\xc1")
            for index, value in enumerate(values, 1):
                self.argument(index, value)
        self.call(name)

    def image(self):
        assert len(self.code) <= 4096
        text_raw = max(0x400, (len(self.code) + 511) & ~511)
        data_raw = 0x200 + text_raw
        data = bytearray(data_raw + len(self.data))
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        size = 240 if self.bits == 64 else 224
        struct.pack_into("<HHIIIHH", data, 0x84,
                         0x8664 if self.bits == 64 else 0x14c, 2, 0, 0, 0, size, 0x22 if self.bits == 64 else 0x102)
        opt = 0x98
        struct.pack_into("<H", data, opt, 0x20b if self.bits == 64 else 0x10b)
        struct.pack_into("<II", data, opt + 4, text_raw, 0x1000)
        struct.pack_into("<I", data, opt + 16, TEXT)
        struct.pack_into("<I", data, opt + 20, TEXT)
        if self.bits == 32:
            struct.pack_into("<I", data, opt + 24, DATA)
        struct.pack_into("<Q" if self.bits == 64 else "<I", data,
                         opt + (24 if self.bits == 64 else 28), self.base)
        struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
        struct.pack_into("<HH", data, opt + 40, 6, 0)
        struct.pack_into("<HH", data, opt + 48, 6, 0)
        struct.pack_into("<II", data, opt + 56, 0x3000, 0x200)
        struct.pack_into("<H", data, opt + 68, 2 if self.gui else 3)
        struct.pack_into("<H", data, opt + 70, 0x100)
        struct.pack_into("<QQQQ" if self.bits == 64 else "<IIII", data, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<I", data, opt + (108 if self.bits == 64 else 92), 16)
        directories = opt + (112 if self.bits == 64 else 96)
        struct.pack_into("<II", data, directories + 8, DATA, self.import_size)
        for i, (name, rva, raw, raw_size, flags) in enumerate([
                (b".text", TEXT, 0x200, text_raw, 0x60000020),
                (b".data", DATA, data_raw, 0x1000, 0xc0000040)]):
            section = opt + size + i * 40
            data[section:section + 8] = name.ljust(8, b"\0")
            struct.pack_into("<IIII", data, section + 8, 0x1000, rva, raw_size, raw)
            struct.pack_into("<I", data, section + 36, flags)
        data[0x200:0x200 + len(self.code)] = self.code
        data[data_raw:] = self.data
        return data


def console(bits=64):
    p = Program([("KERNEL32.dll", n) for n in ("GetStdHandle", "WriteFile", "ExitProcess")], bits)
    text = b"Hello from a Windows EXE on macOS!\r\n"
    message, written = p.blob(text), p.blob(b"\0" * 8)
    p.prologue()
    p.invoke("GetStdHandle", [-11])
    p.handle_call("WriteFile", [p.base + message, len(text), p.base + written, 0], register=0)
    p.exit(37)
    return p


def files(filename="example.txt", bits=64):
    names = ["CreateFileW", "WriteFile", "ReadFile", "CloseHandle", "GetStdHandle", "ExitProcess"]
    p = Program([("KERNEL32.dll", n) for n in names], bits)
    payload = b"LeanWin file round trip.\n"
    name = p.wide(filename)
    content, count, buffer = p.blob(payload), p.blob(b"\0" * 8), p.blob(b"\0" * 128)
    p.prologue()
    p.invoke("CreateFileW", [p.base + name, 0x40000000, 0, 0, 2, 0x80, 0])
    p.save_handle()
    p.handle_call("WriteFile", [p.base + content, len(payload), p.base + count, 0])
    p.handle_call("CloseHandle", [])
    p.invoke("CreateFileW", [p.base + name, 0x80000000, 0, 0, 3, 0x80, 0])
    p.save_handle()
    p.handle_call("ReadFile", [p.base + buffer, 128, p.base + count, 0])
    p.handle_call("CloseHandle", [])
    p.invoke("GetStdHandle", [-11])
    p.handle_call("WriteFile", [p.base + buffer, len(payload), p.base + count, 0], register=0)
    p.exit(0)
    return p


def dialog(bits=64):
    p = Program([("USER32.dll", "MessageBoxW"), ("KERNEL32.dll", "ExitProcess")], bits, gui=True)
    text, title = p.wide("这是真正的 Windows EXE，通过 LeanWin 的接口实现显示在 Mac 上。"), p.wide("LeanWin · Windows 接口验证")
    p.prologue()
    p.invoke("MessageBoxW", [0, p.base + text, p.base + title, 0])
    if bits == 64:
        p.emit(b"\x89\xc1")
    else:
        p.emit(b"\x50")
    p.call("ExitProcess")
    return p


if __name__ == "__main__":
    directory = Path(__file__).resolve().parent / "bin"
    directory.mkdir(exist_ok=True)
    for bits in (32, 64):
        for name, build in [("hello", console), ("files", files), ("dialog", dialog)]:
            (directory / f"{name}{bits}.exe").write_bytes(build(bits=bits).image())
    print(directory)
