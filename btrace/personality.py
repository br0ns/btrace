from .info import *

if PLATFORM == 'linux':
    if MACHINE == 'i386':
        from .syscalls.linux import i386 as sys
        WORDSIZE = [4]
        SYSCALLS = [sys]

    if MACHINE == 'amd64':
        from .syscalls.linux import amd64 as sys0
        from .syscalls.linux import amd64_32 as sys1
        WORDSIZE = [8, 4]
        SYSCALLS = [sys0, sys1]

if MACHINE == 'amd64':
    def personality(tracee):
        cs = tracee.regs.cs
        assert cs in (0x23, 0x33), \
            'unknown personality'
        if cs == 0x23:
            return 1
        return 0

else: # default
    def personality(tracee):
        return 0
