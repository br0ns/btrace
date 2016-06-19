### Constants used by ptrace(2)
# Constants are listed in the order they appear in the man page.
# Sources:
#   /usr/include/sys/ptrace.h
#   /usr/include/linux/ptrace.h
#   /usr/include/x86_64-linux-gnu/asm/ptrace-abi.h

### Requests
from ..info import MACHINE as _MACH

PTRACE_TRACEME               =      0
PTRACE_PEEKTEXT              =      1
PTRACE_PEEKDATA              =      2
PTRACE_PEEKUSER              =      3
PTRACE_POKETEXT              =      4
PTRACE_POKEDATA              =      5
PTRACE_POKEUSER              =      6
PTRACE_GETREGS               =     12
PTRACE_GETFPREGS             =     14
PTRACE_GETREGSET             = 0x4204
PTRACE_SETREGS               =     13
PTRACE_SETFPREGS             =     15
PTRACE_SETREGSET             = 0x4205
PTRACE_GETSIGINFO            = 0x4202
PTRACE_SETSIGINFO            = 0x4203
PTRACE_PEEKSIGINFO           = 0x4209
PTRACE_GETSIGMASK            = 0x420a
PTRACE_SETSIGMASK            = 0x420b
PTRACE_SETOPTIONS            = 0x4200
PTRACE_GETEVENTMSG           = 0x4201
PTRACE_CONT                  =      7
PTRACE_SYSCALL               =     24
PTRACE_SINGLESTEP            =      9
if _MACH == 'amd64':
    PTRACE_SYSEMU            =     31
    PTRACE_SYSEMU_SINGLESTEP =     32
PTRACE_LISTEN                = 0x4208
PTRACE_KILL                  =      8
PTRACE_INTERRUPT             = 0x4207
PTRACE_ATTACH                =     16
PTRACE_SEIZE                 = 0x4206
PTRACE_DETACH                =     17

### Events
PTRACE_EVENT_VFORK           =      2
PTRACE_EVENT_FORK            =      1
PTRACE_EVENT_CLONE           =      3
PTRACE_EVENT_VFORK_DONE      =      5
PTRACE_EVENT_EXEC            =      4
PTRACE_EVENT_EXIT            =      6
PTRACE_EVENT_STOP            =    128
PTRACE_EVENT_SECCOMP         =      7

### Options
PTRACE_O_EXITKILL            = 1 << 20
PTRACE_O_TRACECLONE          = 1 << PTRACE_EVENT_CLONE
PTRACE_O_TRACEEXEC           = 1 << PTRACE_EVENT_EXEC
PTRACE_O_TRACEEXIT           = 1 << PTRACE_EVENT_EXIT
PTRACE_O_TRACEFORK           = 1 << PTRACE_EVENT_FORK
PTRACE_O_TRACESYSGOOD        = 1
PTRACE_O_TRACEVFORK          = 1 << PTRACE_EVENT_VFORK
PTRACE_O_TRACEVFORKDONE      = 1 << PTRACE_EVENT_VFORK_DONE
PTRACE_O_TRACESECCOMP        = 1 << PTRACE_EVENT_SECCOMP
PTRACE_O_SUSPEND_SECCOMP     = 1 << 21
PTRACE_O_MASK                = PTRACE_O_EXITKILL            \
                             | PTRACE_O_TRACECLONE          \
                             | PTRACE_O_TRACEEXEC           \
                             | PTRACE_O_TRACEEXIT           \
                             | PTRACE_O_TRACEFORK           \
                             | PTRACE_O_TRACESYSGOOD        \
                             | PTRACE_O_TRACEVFORK          \
                             | PTRACE_O_TRACEVFORKDONE      \
                             | PTRACE_O_TRACESECCOMP        \
                             | PTRACE_O_SUSPEND_SECCOMP

event_names = {
      2 : 'PTRACE_EVENT_VFORK',
      1 : 'PTRACE_EVENT_FORK',
      3 : 'PTRACE_EVENT_CLONE',
      5 : 'PTRACE_EVENT_VFORK_DONE',
      4 : 'PTRACE_EVENT_EXEC',
      6 : 'PTRACE_EVENT_EXIT',
    128 : 'PTRACE_EVENT_STOP',
      7 : 'PTRACE_EVENT_SECCOMP',
}
