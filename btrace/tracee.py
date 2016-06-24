from .registers import Registers
from .memory import Memory
from .syscall import Syscall
from .siginfo import Siginfo
from .personality import WORDSIZE, SYSCALLS, personality

from .thread_group import ThreadGroup
from .ptrace import ptrace_interrupt

CLONE_PARENT = 0x00008000
CLONE_THREAD = 0x00010000

class Tracee:
    def __init__(self, pid, parent=None, clone_flags=0):
        self.pid = pid

        self.in_syscall = False
        self.is_running = True

        if clone_flags & CLONE_THREAD or clone_flags & CLONE_PARENT:
            self.parent = parent.parent
        else:
            self.parent = parent

        self.ppid = self.parent.pid if self.parent else None

        if clone_flags & CLONE_THREAD:
            self.tgid = parent.tgid
            self.thread_group = parent.thread_group
            self.thread_group.add(self)
        else:
            self.tgid = self.tid
            self.thread_group = set([self])

        self.regs = Registers(self)
        self.mem = Memory(self)
        self.syscall = Syscall(self)
        self.siginfo = Siginfo(self)

        self._waiting_for_interrupt = False

        self.personality = personality(self)

    @property
    def tid(self):
        '''Alias for `self.pid`.'''
        return self.pid

    @property
    def wordsize(self):
        return WORDSIZE[self.personality]

    @property
    def syscalls(self):
        return SYSCALLS[self.personality]

    def _writeback(self):
        self.regs._writeback()
        self.mem._writeback()
        self.siginfo._writeback()

    # def stop(self):
    #     # Need more research
    #     # - http://lxr.free-electrons.com/source/include/linux/errno.h
    #     # - http://stackoverflow.com/questions/29403357/erestart-restartblock-and-restart-syscall-confusion
    #     self._waiting_for_interrupt = True
    #     ptrace_interrupt(self.pid)
