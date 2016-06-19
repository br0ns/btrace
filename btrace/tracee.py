from .registers import Registers
from .memory import Memory
from .syscall import Syscall
from .signal import Signal
from .personality import WORDSIZE, SYSCALLS

from .thread_group import ThreadGroup
from .ptrace import ptrace_interrupt

class Tracee:
    def __init__(self, pid, ppid=None, tg=None):
        self.pid = pid
        self.ppid = ppid

        self.in_syscall = False
        self.is_running = True

        if tg:
            tg.add(self)
            self.thread_group = tg
        else:
            self.thread_group = ThreadGroup(self)

        self.regs = Registers(self)
        self.mem = Memory(self)
        self.syscall = Syscall(self)
        self.signal = Signal(self)
        self.personality = 0

        self._waiting_for_interrupt = False
        self._waiting_for_initial_stop = True

    @property
    def wordsize(self):
        return WORDSIZE[self.personality]

    @property
    def syscalls(self):
        return SYSCALLS[self.personality]

    def _writeback(self):
        self.regs._writeback()
        self.mem._writeback()
        self.signal._writeback()

    # def stop(self):
    #     # Need more research
    #     # - http://lxr.free-electrons.com/source/include/linux/errno.h
    #     # - http://stackoverflow.com/questions/29403357/erestart-restartblock-and-restart-syscall-confusion
    #     self._waiting_for_interrupt = True
    #     ptrace_interrupt(self.pid)
