from . import ptrace

class Siginfo(object):
    _fields = dict(ptrace.regs_t._fields_).keys()

    def __init__(self, tracee):
        self._tracee = tracee
        self._reset()

    def _reset(self):
        self._siginfo = None
        self._dirty = False

    def _init(self):
        self._siginfo = ptrace.ptrace_getsiginfo(self._tracee.pid)

    def _writeback(self):
        if self._dirty:
            ptrace.ptrace_setsiginfo(self._tracee.pid, self._siginfo)
        self._reset()

    def __setattr__(self, k, v):
        if k in self._fields:
            if getattr(self._siginfo, k) != v:
                setattr(self._siginfo, k, v)
                self._dirty = True
        else:
            self.__dict__[k] = v

    def __getattr__(self, k):
        return getattr(self._siginfo, k)
