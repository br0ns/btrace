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
