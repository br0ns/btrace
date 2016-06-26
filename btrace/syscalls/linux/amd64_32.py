# Syscall table is the same as for i386.
from .i386 import *

# But the registers are still 64bit from the tracers viewpoint.
NR = ('reg', 'orig_rax')
ARGS = [
    ('reg', 'rbx'),
    ('reg', 'rcx'),
    ('reg', 'rdx'),
    ('reg', 'rsi'),
    ('reg', 'rdi'),
    ('reg', 'rbp'),
]
RETVAL = ('reg', 'rax')
