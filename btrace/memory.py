import inspect
import ctypes
import collections

from .ptrace import *

def _signed(v, sz):
    '''internal utility function'''
    sbit = 1 << (sz - 1)
    if v & sbit:
        v -= 1 << sz
    return v

def _unsigned(v, sz):
    '''internal utility function'''
    return v & (1 << sz - 1)

class Memory(object):
    def __init__(self, tracee):
        self._tracee = tracee
        self._cache = {}
        self._dirty = set()

    def _cacheflush(self):
        for addr in self._dirty:
            ptrace_poke(self._tracee.pid, addr, self._cache[addr])
        self._cache = {}
        self._dirty = set()

    def _addroff(self, addr):
        mask = self._tracee.wordsize - 1
        waddr = addr & ~mask
        woff = (addr & mask) * 8
        return waddr, woff

    def _read(self, addr):
        addr, off = self._addroff(addr)
        if addr in self._cache:
            word = self._cache[addr]
        else:
            word = ptrace_peek(self._tracee.pid, addr)
            self._cache[addr] = word
        return chr((word >> off) & 0xff)

    def _write(self, addr, val):
        addr, off = self._addroff(addr)
        val = ord(val)
        if addr in self._cache:
            word = self._cache[addr]
            word &= ~(0xff << off)
            word |= val << off
        else:
            word = val << off
        self._cache[addr] = word
        self._dirty.add(addr)

    def __setitem__(self, k, v):
        if isinstance(k, slice):
            for i, addr in enumerate(xrange(k.start, k.stop, k.step or 1)):
                self._write(addr, v[i])
        elif isinstance(v, collections.Sequence):
            for i, v in enumerate(v):
                self._write(k + i, v)
        else:
            self._write(k, v)

    def __getitem__(self, k):
        if isinstance(k, slice):
            out = []
            for addr in xrange(k.start, k.stop, k.step or 1):
                out.append(self._read(addr))
            return ''.join(out)
        else:
            return self._read(k)

    def cstring_at(self, addr):
        s = ''
        while True:
            x = self[addr]
            if x == '\x00':
                break
            s += x
            addr += 1
        return s

    def put_cstring(self, addr, s):
        self[addr] = s + '\x00'

    def chr_at(self, addr):
        return self[addr]

    def put_chr(self, addr, v):
        self[addr] = v

    def word_at(self, addr):
        f = getattr(self, 'u%d_at' % (self._tracee.wordsize * 8))
        f(addr)

    def put_word(self, addr, v):
        f = getattr(self, 'put_u%d' % (self._tracee.wordsize * 8))
        f(addr, v)

    def struct_at(self, addr, struct):
        size = ctypes.sizeof(struct)
        data = self[addr : addr + size]
        if inspect.isclass(struct):
            return struct.from_buffer_copy(data)
        else:
            ctypes.memmove(ctypes.addressof(struct), data, size)
            return struct

    def put_struct(self, addr, struct):
        self[addr] = buffer(struct)[:]

    def u8_at(self, addr):
        return ord(self[addr])

    def put_u8(self, addr, v):
        self[addr] = chr(v)

    def u16_at(self, addr):
        return self.u8_at(addr) | self.u8_at(addr + 1) << 8

    def put_u16(self, addr, v):
        self.put_u8(addr, v & 0xff)
        self.put_u8(addr + 1, v >> 8)

    def u32_at(self, addr):
        return self.u16_at(addr) | self.u16_at(addr + 2) << 16

    def put_u32(self, addr, v):
        self.put_u16(addr, v & 0xffff)
        self.put_u16(addr + 2, v >> 16)

    def u64_at(self, addr):
        return self.u32_at(addr) | self.u32_at(addr + 4) << 32

    def put_u64(self, addr, v):
        self.put_u32(addr, v & 0xffffffff)
        self.put_u32(addr + 4, v >> 32)

    def s8_at(self, addr):
        return _signed(self.u8_at(addr), 8)

    def put_s8(self, addr, v):
        self.put_u8(addr, _unsigned(v, 8))

    def s16_at(self, addr):
        return _signed(self.u16_at(addr), 16)

    def put_s16(self, addr, v):
        self.put_u16(addr, _unsigned(v, 16))

    def s32_at(self, addr):
        return _signed(self.u32_at(addr), 32)

    def put_s32(self, addr, v):
        self.put_u32(addr, _unsigned(v, 32))

    def s64_at(self, addr):
        return _signed(self.u64_at(addr), 64)

    def put_s64(self, addr, v):
        self.put_u64(addr, _unsigned(v, 64))
