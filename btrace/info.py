import sys
import os

if sys.platform.startswith('linux'):
    PLATFORM = 'linux'
else:
    raise NotImplementedError('Platform not supported')

ARCH = os.uname()[4]
if ARCH in ('i386', 'i686'):
    ARCH = 'i386'
    WORDSIZE = 4
    REG_PC = 'eip'
    REG_SP = 'esp'
    from .syscalls.linux import i386 as SYSCALLS

elif ARCH in ('x86_64', 'amd64'):
    ARCH = 'amd64'
    WORDSIZE = 8
    REG_PC = 'rip'
    REG_SP = 'rsp'
    from .syscalls.linux import amd64 as SYSCALLS

else:
    raise NotImplementedError('Architecture not supported')
