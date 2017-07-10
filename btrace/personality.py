from .info import *

def _x86_at_syscall(*instrs):
    def at_syscall(tracee):
        pc = tracee.regs[REG_PC]
        instr = tracee.mem[pc : pc + 2]
        return instr in instrs
    return at_syscall

if PLATFORM == 'linux':
    if MACHINE == 'i386':
        from .syscalls.linux import i386 as sys
        WORDSIZE = [4]
        SYSCALLS = [sys]
        # `int 0x80`, `sysenter`
        AT_SYSCALL = [_x86_at_syscall('\xcd\x80', '\x0f\x34')]

    if MACHINE == 'amd64':
        from .syscalls.linux import amd64 as sys0
        from .syscalls.linux import amd64_32 as sys1
        WORDSIZE = [8, 4]
        SYSCALLS = [sys0, sys1]
        # 0: `int 0x80`, `sysenter`, `syscall`
        # 1: `int 0x80`, `sysenter`
        AT_SYSCALL = [_x86_at_syscall('\xcd\x80', '\x0f\x34', '\x0f\x05'),
                      _x86_at_syscall('\xcd\x80', '\x0f\x34'),
        ]

if MACHINE == 'amd64':
    def personality(tracee):
        cs = tracee.regs.cs
        assert cs in (0x23, 0x33), \
            'unknown personality'
        # Running in 32 bit mode
        if cs == 0x23:
            return 1
        # The tracee is running in 64 bit mode, but it may be doing a 32 bit
        # syscall.  Read the current machine instruction to see if this is the
        # case.  See `is_syscall` in `/linux/arch/x86/um/ptrace_{32,64}.c`.
        if tracee.in_syscall:
            pc = tracee.regs[REG_PC]
            instr = tracee.mem[pc - 2 : pc]
            # `int 0x80` or `sysenter`
            if instr in ('\xcd\x80', '\x0f\x34'):
                return 1
        # 64 bit mode
        return 0

else: # default
    def personality(tracee):
        return 0
