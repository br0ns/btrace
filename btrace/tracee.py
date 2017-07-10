from .registers import Registers
from .memory import Memory
from .syscall import Syscall
from .siginfo import Siginfo
from .personality import WORDSIZE, SYSCALLS, AT_SYSCALL, personality

from .thread_group import ThreadGroup
from .ptrace import ptrace_interrupt

CLONE_PARENT = 0x00008000
CLONE_THREAD = 0x00010000

class Tracee(object):
    def __init__(self, pid, parent=None, clone_flags=0):
        self.pid = pid

        self.in_syscall = False
        self.is_running = True
        self.is_alive   = True

        # Single step a set number of times
        self.singlesteps = 0
        # Keep single stepping
        self.singlestep = False

        # Set parent and parent pid
        if clone_flags & CLONE_THREAD or clone_flags & CLONE_PARENT:
            self.parent = parent.parent
        else:
            self.parent = parent
        self.ppid = self.parent.pid if self.parent else None

        # Set thread group
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

        # "Internal" state
        self._waiting_for_interrupt = False
        self._do_detach = False
        self._was_singlestepped = False

        # We set the personality last as we may need to read from registers
        # and/or memory.
        self.personality = personality(self)

        # Since detecting the personality may have saturated the register/memory
        # caches we need to flush them.
        self._cacheflush()

    def detach(self):
        self._do_detach = True

    @property
    def tid(self):
        '''Alias for `self.pid`.'''
        return self.pid

    @property
    def at_syscall(self):
        return AT_SYSCALL[self.personality](self)

    @property
    def wordsize(self):
        return WORDSIZE[self.personality]

    @property
    def syscalls(self):
        return SYSCALLS[self.personality]

    def _cacheflush(self):
        self.regs._cacheflush()
        self.mem._cacheflush()
        self.siginfo._cacheflush()

    # def stop(self):
    #     # Need more research
    #     # - http://lxr.free-electrons.com/source/include/linux/errno.h
    #     # - http://stackoverflow.com/questions/29403357/erestart-restartblock-and-restart-syscall-confusion
    #     self._waiting_for_interrupt = True
    #     ptrace_interrupt(self.pid)
