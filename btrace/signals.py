SIGHUP    =  1
SIGINT    =  2
SIGQUIT   =  3
SIGILL    =  4
SIGTRAP   =  5
SIGABRT   =  6
SIGBUS    =  7
SIGFPE    =  8
SIGKILL   =  9
SIGUSR1   = 10
SIGSEGV   = 11
SIGUSR2   = 12
SIGPIPE   = 13
SIGALRM   = 14
SIGTERM   = 15
SIGSTKFLT = 16
SIGCHLD   = 17
SIGCONT   = 18
SIGSTOP   = 19
SIGTSTP   = 20
SIGTTIN   = 21
SIGTTOU   = 22
SIGURG    = 23
SIGXCPU   = 24
SIGXFSZ   = 25
SIGVTALRM = 26
SIGPROF   = 27
SIGWINCH  = 28
SIGIO     = 29
SIGPWR    = 30
SIGSYS    = 31
SIGRTMIN  = 34
SIGRTMAX  = 64

# si_code values
SI_USER     =     0
SI_KERNEL   =  0x80
SI_QUEUE    =    -1
SI_TIMER    =    -2
SI_MESGQ    =    -3
SI_ASYNCIO  =    -4
SI_SIGIO    =    -5
SI_TKILL    =    -6
SI_DETHREAD =    -7

signal_names = {
     1: 'SIGHUP',
     2: 'SIGINT',
     3: 'SIGQUIT',
     4: 'SIGILL',
     5: 'SIGTRAP',
     6: 'SIGABRT',
     7: 'SIGBUS',
     8: 'SIGFPE',
     9: 'SIGKILL',
    10: 'SIGUSR1',
    11: 'SIGSEGV',
    12: 'SIGUSR2',
    13: 'SIGPIPE',
    14: 'SIGALRM',
    15: 'SIGTERM',
    16: 'SIGSTKFLT',
    17: 'SIGCHLD',
    18: 'SIGCONT',
    19: 'SIGSTOP',
    20: 'SIGTSTP',
    21: 'SIGTTIN',
    22: 'SIGTTOU',
    23: 'SIGURG',
    24: 'SIGXCPU',
    25: 'SIGXFSZ',
    26: 'SIGVTALRM',
    27: 'SIGPROF',
    28: 'SIGWINCH',
    29: 'SIGIO',
    30: 'SIGPWR',
    31: 'SIGSYS',
    34: 'SIGRTMIN',
    35: 'SIGRTMIN+1',
    36: 'SIGRTMIN+2',
    37: 'SIGRTMIN+3',
    38: 'SIGRTMIN+4',
    39: 'SIGRTMIN+5',
    40: 'SIGRTMIN+6',
    41: 'SIGRTMIN+7',
    42: 'SIGRTMIN+8',
    43: 'SIGRTMIN+9',
    44: 'SIGRTMIN+10',
    45: 'SIGRTMIN+11',
    46: 'SIGRTMIN+12',
    47: 'SIGRTMIN+13',
    48: 'SIGRTMIN+14',
    49: 'SIGRTMIN+15',
    50: 'SIGRTMAX-14',
    51: 'SIGRTMAX-13',
    52: 'SIGRTMAX-12',
    53: 'SIGRTMAX-11',
    54: 'SIGRTMAX-10',
    55: 'SIGRTMAX-9',
    56: 'SIGRTMAX-8',
    57: 'SIGRTMAX-7',
    58: 'SIGRTMAX-6',
    59: 'SIGRTMAX-5',
    60: 'SIGRTMAX-4',
    61: 'SIGRTMAX-3',
    62: 'SIGRTMAX-2',
    63: 'SIGRTMAX-1',
    64: 'SIGRTMAX',
    }
