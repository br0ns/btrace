import sys
import os

if sys.platform.startswith('linux'):
    PLATFORM = 'linux'
else:
    raise NotImplementedError('Platform not supported')

MACHINE = os.uname()[4]
if MACHINE in ('i386', 'i686'):
    MACHINE = 'i386'
    WORDSIZE = 32
    REG_PC = 'eip'
    REG_SP = 'esp'

elif MACHINE in ('x86_64', 'amd64'):
    MACHINE = 'amd64'
    WORDSIZE = 64
    REG_PC = 'rip'
    REG_SP = 'rsp'

else:
    raise NotImplementedError('Architecture not supported')
