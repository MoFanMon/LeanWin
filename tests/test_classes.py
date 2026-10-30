"""Real PE probes for window-class metadata; no visible windows are created."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe, Program, reg

ROOT=Path(__file__).resolve().parents[1]
CLI=Path(os.environ.get("LEANWIN_CLI",ROOT/"build/leanwin"))
USER={"RegisterClassW","RegisterClassExW","GetClassInfoW","GetClassInfoExW","UnregisterClassW"}
COMMON={"InitCommonControls","InitCommonControlsEx"}

class ClassProbe(Probe):
    def __init__(self,names,bits=64):
        imports=[("USER32.dll" if n in USER else "COMCTL32.dll" if n in COMMON else "KERNEL32.dll",n)
                 for n in dict.fromkeys([*names,"ExitProcess"])]
        Program.__init__(self,imports,bits)
        self.failures=[]; self.prologue()


def class_size(bits,extended=True):
    return (80 if bits==64 else 48) if extended else (72 if bits==64 else 40)


def class_data(p,name,extended=True,**changes):
    fields=dict(style=3,proc=p.base+0x1000,cls_extra=8,wnd_extra=16,instance=p.base,
                icon=0,cursor=0,background=6,menu=123,name=p.base+name,small_icon=0)
    fields.update(changes)
    values=[fields[n] for n in ("style","proc","cls_extra","wnd_extra","instance","icon","cursor","background","menu","name")]
    if extended: values=[class_size(p.bits),*values,fields["small_icon"]]
    fmt=("<IIQiiQQQQQQQ" if extended else "<I4xQiiQQQQQQ") if p.bits==64 else ("<IIIiiIIIIIII" if extended else "<IIiiIIIIII")
    return p.blob(struct.pack(fmt,*values))


def common_classes_probe(bits=64,extended=False):
    p=ClassProbe(["InitCommonControlsEx" if extended else "InitCommonControls","GetClassInfoExW"],bits)
    out=p.blob(struct.pack("<I",class_size(bits))+b"\0"*(class_size(bits)-4))
    if not extended:
        p.call("InitCommonControls")
        names=["SysListView32","SysHeader32","SysTreeView32","ToolbarWindow32","msctls_statusbar32",
               "msctls_trackbar32","tooltips_class32","SysTabControl32","msctls_updown32",
               "msctls_progress32","msctls_hotkey32","SysAnimate32"]
    else:
        names=[]
        for flags,group in [(0x400,["ReBarWindow32"]),(0x100,["SysDateTimePick32","SysMonthCal32"]),
                            (0x200,["ComboBoxEx32"]),(0x800,["SysIPAddress32"]),
                            (0x1000,["SysPager"])]:
            init=p.blob(struct.pack("<II",8,flags))
            p.invoke("InitCommonControlsEx",[p.base+init]); p.nonzero(); names+=group
    for name in names:
        text=p.wide(name)
        p.invoke("GetClassInfoExW",[0,p.base+text,p.base+out]); p.nonzero()
        p.mov(0,p.base+out); p.emit((b"\x48" if bits==64 else b"")+b"\x8b\x40\x08")
        p.nonzero()
    p.finish(); return p


def class_lifecycle_probe(bits=64,extended=True):
    api="RegisterClassExW" if extended else "RegisterClassW"
    query="GetClassInfoExW" if extended else "GetClassInfoW"
    p=ClassProbe([api,query,"UnregisterClassW","GetLastError"],bits)
    name=p.wide("LeanWinProbe"); lower=p.wide("leanwinprobe")
    wc=class_data(p,name,extended); size=class_size(bits,extended)
    p.class_input_rva=wc
    out=p.blob(struct.pack("<I",size)+b"\xcc"*(size-4))
    p.invoke(api,[p.base+wc]); p.nonzero(); p.copy(3,0)
    p.invoke(api,[p.base+wc]); p.equal(0)
    p.call("GetLastError"); p.equal(1410)
    # The registered name must survive mutation of the caller's input.
    p.mov(0,p.base+name); p.emit(b"\x66\xc7\x00X\0")
    p.invoke(query,[p.base,p.base+lower,p.base+out]); p.nonzero()
    p.mov(0,p.base+out)
    offset=4 if extended else 0
    p.require(b"\x81\x78"+bytes([offset])+struct.pack("<I",3))
    proc_offset=8 if extended or bits==64 else 4
    p.emit((b"\x48" if bits==64 else b"")+b"\x8b\x40"+bytes([proc_offset]))
    p.mov(2,p.base+0x1000)
    p.require((b"\x48" if bits==64 else b"")+b"\x39\xd0")
    p.mov(0,p.base+out)
    extra_offset=proc_offset+bits//8
    p.require(b"\x81\x78"+bytes([extra_offset])+struct.pack("<I",8))
    p.require(b"\x81\x78"+bytes([extra_offset+4])+struct.pack("<I",16))
    p.invoke(query,[p.base,reg(3),p.base+out]); p.nonzero()
    p.invoke("UnregisterClassW",[reg(3),p.base]); p.nonzero()
    p.invoke(query,[p.base,p.base+lower,p.base+out]); p.equal(0)
    p.call("GetLastError"); p.equal(1411)
    p.finish(); return p


class ClassTests(unittest.TestCase):
    def run_probe(self,p):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/"classes.exe"; exe.write_bytes(p.image())
            return subprocess.run([str(CLI),"run",str(exe),"--root",str(Path(d)/"drive")],capture_output=True,timeout=5)

    def test_legacy_common_controls_register_queryable_classes(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(common_classes_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_extended_registration_accumulates_class_groups(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(common_classes_probe(bits,True)); self.assertEqual(r.returncode,0,r.stderr)

    def test_custom_class_name_copy_atom_case_lookup_and_unregister(self):
        for bits in (32,64):
            for extended in (False,True):
                with self.subTest(bits=bits,extended=extended):
                    r=self.run_probe(class_lifecycle_probe(bits,extended)); self.assertEqual(r.returncode,0,r.stderr)

    def test_invalid_registration_does_not_reserve_class_name(self):
        p=ClassProbe(["RegisterClassExW","UnregisterClassW","GetLastError"])
        name=p.wide("LeanWinInvalid"); wc=class_data(p,name,cls_extra=-1)
        p.invoke("RegisterClassExW",[p.base+wc]); p.equal(0)
        p.call("GetLastError"); p.equal(87)
        p.mov(0,p.base+wc+16); p.emit(b"\xc7\x00\0\0\0\0")
        p.invoke("RegisterClassExW",[p.base+wc]); p.nonzero()
        p.invoke("UnregisterClassW",[p.base+name,p.base]); p.nonzero(); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_wrong_size_and_unsupported_flags_are_rejected(self):
        p=ClassProbe(["InitCommonControlsEx","GetClassInfoExW","GetLastError"])
        bad=p.blob(struct.pack("<II",7,0x100))
        flags=[p.blob(struct.pack("<II",8,value)) for value in (0x10000,0x8000,0x2000)]
        for value in (bad,*flags):
            p.invoke("InitCommonControlsEx",[p.base+value]); p.equal(0)
        name=p.wide("SysDateTimePick32")
        out=p.blob(struct.pack("<I",80)+b"\xcc"*76)
        p.invoke("GetClassInfoExW",[0,p.base+name,p.base+out]); p.equal(0)
        p.call("GetLastError"); p.equal(1411)
        p.finish(); r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_output_pointer_requires_write_permission_for_entire_class(self):
        p=ClassProbe(["GetClassInfoExW","VirtualAlloc","VirtualProtect"])
        text=p.wide("Button"); old=p.blob(b"\0"*4)
        p.invoke("VirtualAlloc",[0,4096,0x3000,4]); p.nonzero(); p.copy(3,0)
        p.emit(b"\xc7\x00\x50\0\0\0")
        p.invoke("VirtualProtect",[reg(3),4096,2,p.base+old]); p.nonzero()
        p.invoke("GetClassInfoExW",[0,p.base+text,reg(3)]); p.exit(99)
        r=self.run_probe(p); self.assertEqual(r.returncode,65,r.stderr); self.assertIn(b"protection violation",r.stderr)

    def test_register_rejects_non_executable_window_procedure(self):
        p=ClassProbe(["RegisterClassExW","GetLastError"])
        name=p.wide("LeanWinBadProc"); wc=class_data(p,name,proc=p.base+name)
        p.invoke("RegisterClassExW",[p.base+wc]); p.equal(0)
        p.call("GetLastError"); p.equal(87); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

    def test_module_exports_are_scoped_to_the_correct_dll(self):
        p=ClassProbe(["LoadLibraryW","GetProcAddress","InitCommonControlsEx","GetLastError"])
        dll=p.wide("COMCTL32.dll"); wrong=p.wide("USER32.dll")
        symbol=p.blob(b"InitCommonControlsEx\0"); init=p.blob(struct.pack("<II",8,0x20))
        p.invoke("LoadLibraryW",[p.base+dll]); p.nonzero(); p.copy(3,0)
        p.invoke("GetProcAddress",[reg(3),p.base+symbol]); p.nonzero(); p.copy(6,0)
        p.argument(0,p.base+init); p.emit(b"\xff\xd6"); p.nonzero()
        p.invoke("LoadLibraryW",[p.base+wrong]); p.nonzero()
        p.invoke("GetProcAddress",[reg(0),p.base+symbol]); p.equal(0)
        p.call("GetLastError"); p.equal(127); p.finish()
        r=self.run_probe(p); self.assertEqual(r.returncode,0,r.stderr)

if __name__=="__main__": unittest.main()
