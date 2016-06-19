from . import ptrace

class Registers(object):
    names = dict(ptrace.regs_t._fields_).keys()

    def __init__(self, tracee):
        self._tracee = tracee
        self._reset()

    def _reset(self):
        self._regs = None
        self._dirty = False

    def _writeback(self):
        if self._dirty:
            ptrace.ptrace_setregs(self._tracee.pid, self._regs)
        self._reset()

    def __getattr__(self, k):
        return self[k]

    def __setattr__(self, k, v):
        if k in self.names:
            self[k] = v
        else:
            self.__dict__[k] = v

    def _check(self, r):
        if r not in self.names:
            raise KeyError('unknown register: %s' % r)
        if not self._regs:
            self._regs = ptrace.ptrace_getregs(self._tracee.pid)

    def __getitem__(self, r):
        self._check(r)
        return getattr(self._regs, r)

    def __setitem__(self, r, v):
        self._check(r)
        if self[r] != v:
            setattr(self._regs, r, v)
            self._dirty = True
