from .ptrace import *

class Memory(object):
    def __init__(self, tracee):
        self._tracee = tracee
        self._cache = {}
        self._dirty = set()

    def _writeback(self):
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
        val = (word >> off) & 0xff
        return val

    def _write(self, addr, val):
        addr, off = self._addroff(addr)
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
            for i, addr in enumerate(xrange(k.start, k.stop, k.step)):
                self._write(addr, v[i])
        elif hasattr(v, '__iter__'):
            for i, v in enumerate(v):
                self._write(k + i, v)
        else:
            self._write(k, v)

    def __getitem__(self, k):
        if isinstance(k, slice):
            out = []
            for addr in xrange(k.start, k.stop, k.step):
                out.append(self._read(addr))
            return out
        else:
            return self._read(k)

    def cstring_at(self, addr):
        s = ''
        while True:
            x = self[addr]
            if x == 0:
                break
            s += chr(x)
            addr += 1
        return s

    def put_cstring(self, addr, s):
        for i, c in enumerate(s):
            self[addr + i] = ord(c)
