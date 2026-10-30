"""Real x86/x64 PE probes for guest atomic read/modify/write operations."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from kernel_fixture import Probe, reg

ROOT=Path(__file__).resolve().parents[1]
CLI=Path(os.environ.get('LEANWIN_CLI',ROOT/'build/leanwin'))


def operand_prefix(width):
    return b'\x66' if width==16 else b'\x48' if width==64 else b''


def check_memory(p,width,value):
    p.emit(operand_prefix(width)+(b'\x8a\x03' if width==8 else b'\x8b\x03'))
    if width<32: p.emit(b'\x25'+struct.pack('<I',(1<<width)-1))
    if width==64:
        p.mov(2,value); p.require(b'\x48\x39\xd0')
    else: p.equal(value)


def atomic_arithmetic_probe(bits=64):
    p=Probe([],bits)
    for width in (8,16,32,*([64] if bits==64 else [])):
        slot=p.blob(b'\xff'*8); p.mov(3,p.base+slot)
        prefix=b'\xf0'+operand_prefix(width)
        p.mov(0,0); p.emit(b'\x83\xf8\x01')  # carry set
        p.emit(prefix+bytes([0xfe if width==8 else 0xff,0x03]))
        p.require(b'',0x83); p.require(b'',0x85)  # INC preserves CF, sets ZF
        check_memory(p,width,0)
        p.emit(prefix+bytes([0xfe if width==8 else 0xff,0x0b]))
        check_memory(p,width,(1<<width)-1)
        p.emit(prefix+bytes([0xf6 if width==8 else 0xf7,0x13]))
        check_memory(p,width,0)
        p.emit(prefix+bytes([0xf6 if width==8 else 0xf7,0x1b]))
        p.require(b'',0x82)  # NEG(0) clears CF
        p.mov(1,7); p.emit(prefix+bytes([0x00 if width==8 else 0x01,0x0b]))
        check_memory(p,width,7)
        p.mov(1,2); p.emit(prefix+bytes([0x28 if width==8 else 0x29,0x0b]))
        check_memory(p,width,5)
        p.emit(prefix+bytes([0xf6 if width==8 else 0xf7,0x1b]))
        p.require(b'',0x83)  # NEG(nonzero) sets CF
        check_memory(p,width,((1<<width)-5))
    p.finish(); return p


def atomic_immediate_probe(bits=64):
    p=Probe([],bits)
    for width in (8,16,32,*([64] if bits==64 else [])):
        slot=p.blob(b'\0'*8); p.mov(3,p.base+slot)
        opcode=0x80 if width==8 else 0x83
        prefix=b'\xf0'+operand_prefix(width)+bytes([opcode])
        for operation,imm,want in [(0,7,7),(1,8,15),(4,3,3),(6,6,5),(5,1,4),
                                   (2,1,6),(3,1,4),(0,0xff,3)]:
            if operation in (2,3):
                p.mov(0,0); p.emit(b'\x83\xf8\x01')
            p.emit(prefix+bytes([3|(operation<<3),imm])); check_memory(p,width,want)
        if width!=8:
            p.emit(b'\xf0'+operand_prefix(width)+b'\x81\x03'+(b'\x34\x12' if width==16 else b'\x34\x12\0\0'))
            check_memory(p,width,0x1237)
    # RIP-relative effective address must include the trailing immediate.
    if bits==64:
        slot=p.blob(b'\0'*4)
        displacement=slot-(0x1000+len(p.code)+8)
        p.emit(b'\xf0\x83\x05'+struct.pack('<i',displacement)+b'\x09')
        p.mov(3,p.base+slot); check_memory(p,32,9)
    p.finish(); return p


def atomic_exchange_probe(bits=64):
    p=Probe([],bits)
    for width in (8,16,32,*([64] if bits==64 else [])):
        slot=p.blob((5).to_bytes(8,'little')); p.mov(3,p.base+slot); p.mov(1,7)
        prefix=operand_prefix(width)
        p.mov(0,0); p.emit(b'\x83\xf8\x01')
        p.emit(prefix+bytes([0x86 if width==8 else 0x87,0x0b]))
        p.require(b'',0x83)  # XCHG leaves flags alone
        p.copy(0,1); p.equal(5); check_memory(p,width,7)
        p.mov(1,2); p.emit(b'\xf0'+prefix+b'\x0f'+bytes([0xc0 if width==8 else 0xc1,0x0b]))
        p.copy(0,1); p.equal(7); check_memory(p,width,9)
        for accumulator,source,want_acc,want_mem,success in [(9,11,9,11,True),(8,13,11,11,False)]:
            p.mov(0,accumulator); p.mov(1,source)
            p.emit(b'\xf0'+prefix+b'\x0f'+bytes([0xb0 if width==8 else 0xb1,0x0b]))
            p.require(b'',0x85 if success else 0x84); p.equal(want_acc)
            check_memory(p,width,want_mem)
    # Aliasing XADD operands must leave the sum in the destination register.
    p.mov(0,7); p.emit(b'\x0f\xc1\xc0'); p.equal(14)
    # AH is selected without REX; a bare REX selects SIL rather than DH.
    slot=p.blob(b'\x05'+b'\0'*7); p.mov(3,p.base+slot); p.mov(0,0x1234)
    p.emit(b'\xf0\x0f\xc0\x23'); p.equal(0x0534); check_memory(p,8,23)
    if bits==64:
        p.mov(6,2); p.emit(b'\xf0\x40\x0f\xc0\x33'); p.copy(0,6); p.equal(23)
        check_memory(p,8,25)
    p.finish(); return p


def short_exchange_probe(bits=64):
    p=Probe([],bits)
    for width in (16,32,*([64] if bits==64 else [])):
        initial=0x1122334455667788 if bits==64 else 0x55667788
        other=0x9988776655443322 if bits==64 else 0x55443322
        p.mov(0,initial); p.mov(1,other)
        p.emit(operand_prefix(width)+b'\x91')
        want=(initial & ~((1<<width)-1))|(other & ((1<<width)-1)) if width==16 else other&((1<<width)-1)
        p.mov(2,want); p.require((b'\x48' if bits==64 else b'')+b'\x39\xd0')
        p.copy(0,1)
        want=(other & ~0xffff)|(initial&0xffff) if width==16 else initial&((1<<width)-1)
        p.mov(2,want); p.require((b'\x48' if bits==64 else b'')+b'\x39\xd0')
    if bits==64:
        p.mov(0,0x1122334455667788); p.mov(8,0x9988776655443322); p.emit(b'\x41\x90')
        p.mov(2,0x55443322); p.require(b'\x48\x39\xd0')
        p.copy(0,8); p.mov(2,0x55667788); p.require(b'\x48\x39\xd0')
        p.mov(0,0x1122334455667788); p.emit(b'\x90'); p.mov(2,0x1122334455667788); p.require(b'\x48\x39\xd0')
    p.finish(); return p


def atomic_flags_probe(bits=64):
    p=Probe([],bits)
    for width in (8,16,32,*([64] if bits==64 else [])):
        slot=p.blob(((1<<(width-1))-1).to_bytes(8,'little')); p.mov(3,p.base+slot)
        prefix=b'\xf0'+operand_prefix(width)
        p.mov(0,0); p.emit(b'\x83\xf8\x01')
        p.emit(prefix+bytes([0xfe if width==8 else 0xff,0x03]))
        p.require(b'',0x81); p.require(b'',0x89); p.require(b'',0x83)
        check_memory(p,width,1<<(width-1))
        p.emit(prefix+bytes([0xf6 if width==8 else 0xf7,0x1b]))
        p.require(b'',0x81); p.require(b'',0x83)
        check_memory(p,width,1<<(width-1))
    p.finish(); return p


def register_exchange_probe(bits=64):
    p=Probe([],bits)
    p.mov(0,5); p.mov(1,5); p.mov(2,9); p.emit(b'\x0f\xb1\xd1')
    p.require(b'',0x85); p.equal(5); p.copy(0,1); p.equal(9)
    p.mov(0,7); p.mov(1,11); p.mov(2,9); p.emit(b'\x0f\xb1\xd1')
    p.require(b'',0x84); p.equal(11); p.copy(0,1); p.equal(11)
    if bits==64:
        # CMPXCHG r32 performs a write cycle on both success and failure.
        p.mov(0,0x1122334400000007); p.mov(1,0xaabbccdd0000000b); p.mov(2,9)
        p.emit(b'\x0f\xb1\xd1'); p.mov(2,11); p.require(b'\x48\x39\xd0')
        p.copy(0,1); p.require(b'\x48\x39\xd0')
    p.finish(); return p


def atomic_mutation_probe(bits=64):
    p=Probe([],bits); slot=p.blob(b'\0'*8)
    p.mov(3,p.base+slot); p.mov(1,1)
    p.atomic_offset=len(p.code); p.emit(b'\xf0\x0f\xc1\x0b'); p.exit(0)
    return p


def atomic_prefix_probe(bits=64):
    p=Probe([],bits)
    slot=p.blob(b'\xff'*8); p.mov(3,p.base+slot)
    if bits==64:
        # REX before a legacy prefix is ignored. Only the dword increments.
        p.emit(b'\x49\xf0\xff\x03')
        check_memory(p,64,0xffffffff00000000)
        p.mov(0,0x1122334455667788); p.mov(1,0x9988776655443322); p.mov(9,3)
        p.emit(b'\x49\x66\x87\xc1')  # AX and CX, not RAX and R9.
        p.mov(2,0x1122334455663322); p.require(b'\x48\x39\xd0')
        p.copy(0,9); p.equal(3)
    else:
        p.emit(b'\x66\xf0\xff\x03'); check_memory(p,32,0xffff0000)
    p.finish(); return p


def atomic_thread_probe(bits=64):
    p=Probe(['CreateThread','WaitForSingleObject','GetExitCodeThread','CloseHandle'],bits)
    start=p.blob(b'\0'*8); counter=p.blob(b'\0'*4); code=p.blob(b'\0'*4)
    for target in (3,6):
        p.mov(0,p.base+start); p.emit((b'\x48' if bits==64 else b'')+b'\x8b\x38')
        p.invoke('CreateThread',[0,0,reg(7),0,0,0]); p.nonzero(); p.copy(target,0)
    for target in (3,6):
        p.invoke('WaitForSingleObject',[reg(target),0xffffffff]); p.equal(0)
        p.invoke('GetExitCodeThread',[reg(target),p.base+code]); p.nonzero()
        p.mov(0,p.base+code); p.require(b'\x83\x38\0')
        p.invoke('CloseHandle',[reg(target)]); p.nonzero()
    p.mov(3,p.base+counter); check_memory(p,32,2000); p.finish()
    struct.pack_into('<Q' if bits==64 else '<I',p.data,start-0x2000,p.base+0x1000+len(p.code))
    # Preserve nonvolatile EBX/RBX as native Windows requires for a thread entry.
    p.emit(b'\x53'); p.mov(3,p.base+counter); p.mov(2,1000); loop=len(p.code)
    p.emit(b'\xf0\xff\x03\x83\xea\x01\x0f\x85'+struct.pack('<i',loop-len(p.code)-12))
    p.emit(b'\x5b\x31\xc0'+(b'\xc3' if bits==64 else b'\xc2\x04\0'))
    return p


class AtomicTests(unittest.TestCase):
    def run_probe(self,p):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'atomic.exe'; exe.write_bytes(p.image())
            return subprocess.run([str(CLI),'run',str(exe),'--root',str(Path(d)/'drive')],capture_output=True,timeout=5)

    def test_locked_arithmetic_preserves_carry_and_updates_full_operand(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(atomic_arithmetic_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_locked_immediates_sign_extend_and_use_complete_rip_relative_address(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(atomic_immediate_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_exchange_add_and_compare_exchange_keep_old_values_flags_and_byte_registers(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(atomic_exchange_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_guest_threads_increment_one_counter_without_lost_updates(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(atomic_thread_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_short_register_exchange_respects_width_extended_register_and_nop(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(short_exchange_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_atomic_signed_overflow_sign_and_carry_flags(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(atomic_flags_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_register_compare_exchange_success_failure_and_zero_extension(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(register_exchange_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_lock_and_rex_prefix_order_selects_the_actual_operand_width(self):
        for bits in (32,64):
            with self.subTest(bits=bits):
                r=self.run_probe(atomic_prefix_probe(bits)); self.assertEqual(r.returncode,0,r.stderr)

    def test_invalid_lock_encodings_are_rejected(self):
        for instruction in (b'\xf0\x90',b'\xf0\xff\xc0',b'\xf0\x83\x3b\0',
                            b'\xf0\x89\x03',b'\xf0\x03\x03',b'\xf0\x0f\xc1\xc0'):
            p=Probe([]); slot=p.blob(b'\0'*8); p.mov(3,p.base+slot); p.emit(instruction); p.exit(99)
            with self.subTest(instruction=instruction):
                r=self.run_probe(p); self.assertEqual(r.returncode,65,r.stderr); self.assertIn(b'LOCK',r.stderr)

    def test_compare_exchange_failure_still_requires_write_access(self):
        p=Probe(['VirtualAlloc','VirtualProtect']); old=p.blob(b'\0'*4)
        p.invoke('VirtualAlloc',[0,4096,0x3000,4]); p.nonzero(); p.copy(3,0)
        p.invoke('VirtualProtect',[reg(3),4096,2,p.base+old]); p.nonzero()
        p.mov(0,7); p.mov(1,9); p.emit(b'\xf0\x0f\xb1\x0b'); p.exit(99)
        r=self.run_probe(p); self.assertEqual(r.returncode,65,r.stderr); self.assertIn(b'protection violation',r.stderr)

    def test_locked_operand_crossing_unmapped_page_fails_cleanly(self):
        p=Probe(['VirtualAlloc'])
        p.invoke('VirtualAlloc',[0,4096,0x3000,4]); p.nonzero(); p.copy(3,0)
        p.emit(b'\x48\x81\xc3\xfe\x0f\0\0\xf0\xff\x03'); p.exit(99)
        r=self.run_probe(p); self.assertEqual(r.returncode,65,r.stderr); self.assertIn(b'protection violation',r.stderr)

if __name__=='__main__': unittest.main()
