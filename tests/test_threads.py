import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from kernel_fixture import Probe, reg
from test_tls import TLSProgram

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))


def thread_probe(bits=64):
    p = Probe(["CreateThread", "ResumeThread", "WaitForSingleObject", "GetExitCodeThread", "CloseHandle"], bits)
    start, data, code = p.blob(b"\0" * 8), p.blob(b"\0" * 8), p.blob(b"\0" * 4)
    p.mov(0, p.base + start); p.emit((b"\x48" if bits == 64 else b"") + b"\x8b\x38")
    p.invoke("CreateThread", [0, 0, reg(7), p.base + data, 4, 0]); p.nonzero(); p.copy(3, 0)
    p.invoke("WaitForSingleObject", [reg(3), 0]); p.equal(258)
    p.invoke("GetExitCodeThread", [reg(3), p.base + code]); p.equal(1)
    p.mov(0, p.base + code); p.require(b"\x81\x38\x03\x01\0\0")
    p.invoke("ResumeThread", [reg(3)]); p.equal(1)
    p.invoke("WaitForSingleObject", [reg(3), 0xffffffff]); p.equal(0)
    p.invoke("GetExitCodeThread", [reg(3), p.base + code]); p.equal(1)
    p.mov(0, p.base + code); p.require(b"\x81\x38\x25\0\0\0")
    p.mov(0, p.base + data); p.require(b"\x81\x38\x11\0\0\0")
    p.invoke("CloseHandle", [reg(3)]); p.equal(1); p.finish()
    struct.pack_into("<Q" if bits == 64 else "<I", p.data, start-0x2000, p.base+0x1000+len(p.code))
    p.emit(b"\xc7\x01\x11\0\0\0\xb8\x25\0\0\0\xc3" if bits == 64 else
           b"\x8b\x44\x24\x04\xc7\x00\x11\0\0\0\xb8\x25\0\0\0\xc2\x04\0")
    return p


def event_probe(bits=64):
    p = Probe(["CreateEventW", "SetEvent", "ResetEvent", "WaitForSingleObject", "CloseHandle"], bits)
    for manual in (0, 1):
        p.invoke("CreateEventW", [0, manual, 0, 0]); p.nonzero(); p.copy(3, 0)
        p.invoke("WaitForSingleObject", [reg(3), 0]); p.equal(258)
        p.invoke("SetEvent", [reg(3)]); p.equal(1)
        p.invoke("WaitForSingleObject", [reg(3), 0]); p.equal(0)
        p.invoke("WaitForSingleObject", [reg(3), 0]); p.equal(0 if manual else 258)
        p.invoke("ResetEvent", [reg(3)]); p.equal(1)
        p.invoke("WaitForSingleObject", [reg(3), 1]); p.equal(258)
        p.invoke("CloseHandle", [reg(3)]); p.equal(1)
    p.finish()
    return p


class ThreadTLSProbe(TLSProgram):
    copy, invoke, require, equal, nonzero = Probe.copy, Probe.invoke, Probe.require, Probe.equal, Probe.nonzero


def thread_tls_probe(bits=64):
    p = ThreadTLSProbe(bits, [("KERNEL32.dll", n) for n in
        ("CreateThread", "WaitForSingleObject", "GetExitCodeThread", "ExitProcess")])
    start, detached, code = p.blob(b"\0"*8), p.blob(b"\0"*4), p.blob(b"\0"*4)
    p.prologue(); p.tls_pointer(); p.require(b"\x83\x38\x21")
    p.mov(0, p.base+start); p.emit((b"\x48" if bits == 64 else b"")+b"\x8b\x38")
    p.invoke("CreateThread", [0, 0, reg(7), 0, 0, 0]); p.nonzero(); p.copy(3, 0)
    p.invoke("WaitForSingleObject", [reg(3), 0xffffffff]); p.equal(0)
    p.invoke("GetExitCodeThread", [reg(3), p.base+code]); p.equal(1)
    p.mov(0, p.base+code); p.require(b"\x83\x38\x25")
    p.mov(0, p.base+detached); p.require(b"\x83\x38\x01")
    p.tls_pointer(); p.require(b"\x83\x38\x21"); p.exit(0)
    struct.pack_into("<Q" if bits == 64 else "<I", p.data, start-0x2000, p.base+0x1000+len(p.code))
    p.tls_pointer(); p.require(b"\x83\x38\x22")
    p.emit(b"\xc7\x00\x33\0\0\0\xb8\x25\0\0\0")
    p.emit(b"\xc3" if bits == 64 else b"\xc2\x04\0")
    p.callback()
    if bits == 32: p.emit(b"\x8b\x54\x24\x08")
    p.emit(b"\x83\xfa\0\x75" + bytes([1 if bits == 64 else 3])); p.callback_return()
    # Keep the notification reason across tls_pointer's scratch registers.
    p.copy(0, 2); p.emit(b"\x50"); p.tls_pointer(); p.emit(b"\x5a")
    p.emit(b"\x83\xfa\x03\x0f\x84\0\0\0\0"); detach_branch = len(p.code)-4
    p.require(b"\x81\x38\x11\x22\x33\x44")
    p.emit(b"\x83\xc2\x20\x89\x10"); p.callback_return()
    struct.pack_into("<i", p.code, detach_branch, len(p.code)-detach_branch-4)
    p.require(b"\x83\x38\x33")
    p.mov(0, p.base+detached); p.emit(b"\xc7\x00\x01\0\0\0"); p.callback_return()
    failure = len(p.code); p.prologue(); p.exit(99)
    for offset in p.failures: struct.pack_into("<i", p.code, offset, failure-offset-4)
    return p


class ThreadTests(unittest.TestCase):
    def run_program(self, p):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threads.exe"
            path.write_bytes(p.image())
            return subprocess.run([str(CLI), "run", str(path), "--root", str(Path(directory) / "drive")],
                                  capture_output=True, timeout=5)

    def test_suspended_thread_runs_on_resume_and_wait_observes_its_exit(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                result = self.run_program(thread_probe(bits))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_auto_and_manual_reset_events_have_real_signal_and_timeout_state(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                result = self.run_program(event_probe(bits))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_dynamic_tls_is_independent_between_threads(self):
        p = Probe(["CreateThread", "WaitForSingleObject", "GetExitCodeThread", "TlsAlloc", "TlsSetValue", "TlsGetValue", "TlsFree"])
        start, index, code = p.blob(b"\0" * 8), p.blob(b"\0" * 4), p.blob(b"\0" * 4)
        p.call("TlsAlloc"); p.copy(6, 0)
        p.mov(0, p.base+index); p.emit(b"\x89\x30")
        p.invoke("TlsSetValue", [reg(6), 17]); p.equal(1)
        p.mov(0, p.base+start); p.emit(b"\x48\x8b\x38")
        p.invoke("CreateThread", [0, 0, reg(7), 0, 0, 0]); p.nonzero(); p.copy(3, 0)
        p.invoke("WaitForSingleObject", [reg(3), 0xffffffff]); p.equal(0)
        p.invoke("GetExitCodeThread", [reg(3), p.base+code]); p.equal(1)
        p.mov(0, p.base+code); p.require(b"\x83\x38\0")
        p.invoke("TlsGetValue", [reg(6)]); p.equal(17)
        p.invoke("TlsFree", [reg(6)]); p.equal(1); p.finish()
        struct.pack_into("<Q", p.data, start-0x2000, p.base+0x1000+len(p.code))
        p.prologue(); p.mov(0, p.base+index); p.emit(b"\x8b\x08"); p.call("TlsGetValue")
        p.emit(b"\x48\x83\xc4\x68\xc3")
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_static_tls_thread_notifications_copy_templates_and_run_detach_before_wait_returns(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                result = self.run_program(thread_tls_probe(bits))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_dynamic_tls_apis_and_direct_teb_access_share_the_same_slots(self):
        for bits in (32, 64):
            p = Probe(["TlsAlloc", "TlsGetValue"], bits)
            p.call("TlsAlloc"); p.equal(0)
            p.emit(b"\x65\xc7\x04\x25\x80\x14\0\0\x35\0\0\0" if bits == 64 else
                   b"\x64\xc7\x05\x10\x0e\0\0\x35\0\0\0")
            p.invoke("TlsGetValue", [0]); p.equal(53); p.finish()
            with self.subTest(bits=bits):
                result = self.run_program(p)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_current_process_and_thread_handles_report_active_status(self):
        p = Probe(["GetCurrentProcess", "GetExitCodeProcess", "GetCurrentThread", "GetCurrentThreadId", "GetExitCodeThread"])
        code = p.blob(b"\0" * 4)
        p.call("GetCurrentProcess")
        p.invoke("GetExitCodeProcess", [reg(0), p.base+code]); p.equal(1)
        p.mov(0, p.base+code); p.require(b"\x81\x38\x03\x01\0\0")
        p.call("GetCurrentThread")
        p.invoke("GetExitCodeThread", [reg(0), p.base+code]); p.equal(1)
        p.mov(0, p.base+code); p.require(b"\x81\x38\x03\x01\0\0")
        p.call("GetCurrentThreadId"); p.nonzero(); p.finish()
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_critical_sections_serialize_threads_across_explicit_yields(self):
        p = Probe(["CreateThread", "WaitForSingleObject", "InitializeCriticalSection", "EnterCriticalSection",
                   "LeaveCriticalSection", "DeleteCriticalSection", "SwitchToThread"])
        start, counter, lock = p.blob(b"\0" * 8), p.blob(b"\0" * 4), p.blob(b"\0" * 40)
        p.invoke("InitializeCriticalSection", [p.base+lock])
        p.mov(0, p.base+start); p.emit(b"\x48\x8b\x38")
        p.invoke("CreateThread", [0, 0, reg(7), 0, 0, 0]); p.nonzero(); p.copy(3, 0)
        p.invoke("CreateThread", [0, 0, reg(7), 0, 0, 0]); p.nonzero(); p.copy(6, 0)
        p.invoke("WaitForSingleObject", [reg(3), 0xffffffff]); p.equal(0)
        p.invoke("WaitForSingleObject", [reg(6), 0xffffffff]); p.equal(0)
        p.mov(0, p.base+counter); p.require(b"\x83\x38\x02")
        p.invoke("DeleteCriticalSection", [p.base+lock]); p.finish()
        struct.pack_into("<Q", p.data, start-0x2000, p.base+0x1000+len(p.code))
        p.emit(b"\x53\x48\x83\xec\x20")
        p.invoke("EnterCriticalSection", [p.base+lock])
        p.mov(0, p.base+counter); p.emit(b"\x8b\x18")
        p.call("SwitchToThread")
        p.emit(b"\x83\xc3\x01")
        p.mov(0, p.base+counter); p.emit(b"\x89\x18")
        p.invoke("LeaveCriticalSection", [p.base+lock])
        p.emit(b"\x48\x83\xc4\x20\x5b\xb8\0\0\0\0\xc3")
        result = self.run_program(p)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
