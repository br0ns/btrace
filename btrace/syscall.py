import time

from .info import REG_SP

class _RW(object):
    def _read(self, (typ, loc)):
        if typ == 'reg':
            return self._tracee.regs[loc]
        else:
            wordsize = loc + WORDSIZE[self._tracee.personality]
            addr = self._tracee.regs[REG_SP] + offset
            return self._tracee.mem[addr]

    def _write(self, (typ, loc), val):
        if typ == 'reg':
            self._tracee.regs[loc] = val
        else:
            wordsize = loc + WORDSIZE[self._tracee.personality]
            addr = self._tracee.regs[REG_SP] + offset
            self._tracee.mem[addr] = val

class Arguments(_RW):
    def __init__(self, tracee):
        self._tracee = tracee

    def __getitem__(self, i):
        return self._read(self._tracee.syscalls.ARGS[i])

    def __setitem__(self, i, x):
        self._write(self._tracee.syscalls.ARGS[i], x)

class Syscall(_RW):
    def __init__(self, tracee):
        self.emulated = False
        self.args = Arguments(tracee)
        self._tracee = tracee
        self._nr = None

        self.started_at = None
        self.stopped_at = None

    def _get_nr(self):
        return self._read(self._tracee.syscalls.NR)

    def _init(self):
        self._nr = self._get_nr()
        self.started_at = time.time()

    def _fini(self):
        self.stopped_at = time.time()
        self.time = self.stopped_at - self.started_at

    @property
    def nr(self):
        return self._nr

    @nr.setter
    def nr(self, val):
        self._nr = nr
        self._write(self._tracee.syscalls.NR, val)

    @property
    def name(self):
        return self._tracee.syscalls.syscall_names[self.nr]

    @name.setter
    def name(self, val):
        self.nr = getattr(self._tracee.syscalls, 'SYS_' + val)

    @property
    def retval(self):
        return self._read(self._tracee.syscalls.RETVAL)

    @retval.setter
    def retval(self, val):
        self._write(self._tracee.syscalls.RETVAL, val)
