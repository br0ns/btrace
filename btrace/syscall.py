import time

from .info import REG_SP, WORDSIZE

_sbit = 1 << (WORDSIZE * 8 - 1)
_smin = -(1 << WORDSIZE * 8)
_mask = (1 << WORDSIZE * 8) - 1

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

        # Timers.
        self.started_at = None
        self.stopped_at = None

    def _get_nr(self):
        return self._read(self._tracee.syscalls.NR)

    def _init(self):
        # The `execve` syscall may change the personality of a tracee, so we record
        # the personality at the time of the call.
        self.personality = self._tracee.personality

        # Setting `nr` as opposed to `_nr` has the side-effect of also setting
        # `_name`.  Since `execve` may change the personality -- and therefore
        # syscall numbers -- of a tracee, we need to look up the name now, not
        # later.
        self.nr = self._get_nr()
        self.started_at = time.time()

    def _fini(self):
        self.stopped_at = time.time()
        self.time = self.stopped_at - self.started_at

    @property
    def nr(self):
        return self._nr

    @nr.setter
    def nr(self, val):
        self._nr = val
        self._name = self._tracee.syscalls.syscall_names[val]
        self._write(self._tracee.syscalls.NR, val)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, val):
        self.nr = getattr(self._tracee.syscalls, 'SYS_' + val)

    @property
    def retval(self):
        r = self._read(self._tracee.syscalls.RETVAL)
        if r & _sbit:
            r += _smin
        return r

    @retval.setter
    def retval(self, val):
        self._write(self._tracee.syscalls.RETVAL, val & _mask)
