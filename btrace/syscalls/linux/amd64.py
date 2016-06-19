NR = ('reg', 'orig_rax')
ARGS = [
    ('reg', 'rdi'),
    ('reg', 'rsi'),
    ('reg', 'rdx'),
    ('reg', 'r10'),
    ('reg', 'r8' ),
    ('reg', 'r9' ),
]
RETVAL = ('reg', 'rax')

SYS_read                   =   0
SYS_write                  =   1
SYS_open                   =   2
SYS_close                  =   3
SYS_stat                   =   4
SYS_fstat                  =   5
SYS_lstat                  =   6
SYS_poll                   =   7
SYS_lseek                  =   8
SYS_mmap                   =   9
SYS_mprotect               =  10
SYS_munmap                 =  11
SYS_brk                    =  12
SYS_rt_sigaction           =  13
SYS_rt_sigprocmask         =  14
SYS_rt_sigreturn           =  15
SYS_ioctl                  =  16
SYS_pread                  =  17
SYS_pwrite                 =  18
SYS_readv                  =  19
SYS_writev                 =  20
SYS_access                 =  21
SYS_pipe                   =  22
SYS_select                 =  23
SYS_sched_yield            =  24
SYS_mremap                 =  25
SYS_msync                  =  26
SYS_mincore                =  27
SYS_madvise                =  28
SYS_shmget                 =  29
SYS_shmat                  =  30
SYS_shmctl                 =  31
SYS_dup                    =  32
SYS_dup2                   =  33
SYS_pause                  =  34
SYS_nanosleep              =  35
SYS_getitimer              =  36
SYS_alarm                  =  37
SYS_setitimer              =  38
SYS_getpid                 =  39
SYS_sendfile               =  40
SYS_socket                 =  41
SYS_connect                =  42
SYS_accept                 =  43
SYS_sendto                 =  44
SYS_recvfrom               =  45
SYS_sendmsg                =  46
SYS_recvmsg                =  47
SYS_shutdown               =  48
SYS_bind                   =  49
SYS_listen                 =  50
SYS_getsockname            =  51
SYS_getpeername            =  52
SYS_socketpair             =  53
SYS_setsockopt             =  54
SYS_getsockopt             =  55
SYS_clone                  =  56
SYS_fork                   =  57
SYS_vfork                  =  58
SYS_execve                 =  59
SYS_exit                   =  60
SYS_wait4                  =  61
SYS_kill                   =  62
SYS_uname                  =  63
SYS_semget                 =  64
SYS_semop                  =  65
SYS_semctl                 =  66
SYS_shmdt                  =  67
SYS_msgget                 =  68
SYS_msgsnd                 =  69
SYS_msgrcv                 =  70
SYS_msgctl                 =  71
SYS_fcntl                  =  72
SYS_flock                  =  73
SYS_fsync                  =  74
SYS_fdatasync              =  75
SYS_truncate               =  76
SYS_ftruncate              =  77
SYS_getdents               =  78
SYS_getcwd                 =  79
SYS_chdir                  =  80
SYS_fchdir                 =  81
SYS_rename                 =  82
SYS_mkdir                  =  83
SYS_rmdir                  =  84
SYS_creat                  =  85
SYS_link                   =  86
SYS_unlink                 =  87
SYS_symlink                =  88
SYS_readlink               =  89
SYS_chmod                  =  90
SYS_fchmod                 =  91
SYS_chown                  =  92
SYS_fchown                 =  93
SYS_lchown                 =  94
SYS_umask                  =  95
SYS_gettimeofday           =  96
SYS_getrlimit              =  97
SYS_getrusage              =  98
SYS_sysinfo                =  99
SYS_times                  = 100
SYS_ptrace                 = 101
SYS_getuid                 = 102
SYS_syslog                 = 103
SYS_getgid                 = 104
SYS_setuid                 = 105
SYS_setgid                 = 106
SYS_geteuid                = 107
SYS_getegid                = 108
SYS_setpgid                = 109
SYS_getppid                = 110
SYS_getpgrp                = 111
SYS_setsid                 = 112
SYS_setreuid               = 113
SYS_setregid               = 114
SYS_getgroups              = 115
SYS_setgroups              = 116
SYS_setresuid              = 117
SYS_getresuid              = 118
SYS_setresgid              = 119
SYS_getresgid              = 120
SYS_getpgid                = 121
SYS_setfsuid               = 122
SYS_setfsgid               = 123
SYS_getsid                 = 124
SYS_capget                 = 125
SYS_capset                 = 126
SYS_rt_sigpending          = 127
SYS_rt_sigtimedwait        = 128
SYS_rt_sigqueueinfo        = 129
SYS_rt_sigsuspend          = 130
SYS_sigaltstack            = 131
SYS_utime                  = 132
SYS_mknod                  = 133
SYS_uselib                 = 134
SYS_personality            = 135
SYS_ustat                  = 136
SYS_statfs                 = 137
SYS_fstatfs                = 138
SYS_sysfs                  = 139
SYS_getpriority            = 140
SYS_setpriority            = 141
SYS_sched_setparam         = 142
SYS_sched_getparam         = 143
SYS_sched_setscheduler     = 144
SYS_sched_getscheduler     = 145
SYS_sched_get_priority_max = 146
SYS_sched_get_priority_min = 147
SYS_sched_rr_get_interval  = 148
SYS_mlock                  = 149
SYS_munlock                = 150
SYS_mlockall               = 151
SYS_munlockall             = 152
SYS_vhangup                = 153
SYS_modify_ldt             = 154
SYS_pivot_root             = 155
SYS__sysctl                = 156
SYS_prctl                  = 157
SYS_arch_prctl             = 158
SYS_adjtimex               = 159
SYS_setrlimit              = 160
SYS_chroot                 = 161
SYS_sync                   = 162
SYS_acct                   = 163
SYS_settimeofday           = 164
SYS_mount                  = 165
SYS_umount2                = 166
SYS_swapon                 = 167
SYS_swapoff                = 168
SYS_reboot                 = 169
SYS_sethostname            = 170
SYS_setdomainname          = 171
SYS_iopl                   = 172
SYS_ioperm                 = 173
SYS_create_module          = 174
SYS_init_module            = 175
SYS_delete_module          = 176
SYS_get_kernel_syms        = 177
SYS_query_module           = 178
SYS_quotactl               = 179
SYS_nfsservctl             = 180
SYS_getpmsg                = 181
SYS_putpmsg                = 182
SYS_afs_syscall            = 183
SYS_tuxcall                = 184
SYS_security               = 185
SYS_gettid                 = 186
SYS_readahead              = 187
SYS_setxattr               = 188
SYS_lsetxattr              = 189
SYS_fsetxattr              = 190
SYS_getxattr               = 191
SYS_lgetxattr              = 192
SYS_fgetxattr              = 193
SYS_listxattr              = 194
SYS_llistxattr             = 195
SYS_flistxattr             = 196
SYS_removexattr            = 197
SYS_lremovexattr           = 198
SYS_fremovexattr           = 199
SYS_tkill                  = 200
SYS_time                   = 201
SYS_futex                  = 202
SYS_sched_setaffinity      = 203
SYS_sched_getaffinity      = 204
SYS_set_thread_area        = 205
SYS_io_setup               = 206
SYS_io_destroy             = 207
SYS_io_getevents           = 208
SYS_io_submit              = 209
SYS_io_cancel              = 210
SYS_get_thread_area        = 211
SYS_lookup_dcookie         = 212
SYS_epoll_create           = 213
SYS_epoll_ctl_old          = 214
SYS_epoll_wait_old         = 215
SYS_remap_file_pages       = 216
SYS_getdents64             = 217
SYS_set_tid_address        = 218
SYS_restart_syscall        = 219
SYS_semtimedop             = 220
SYS_fadvise64              = 221
SYS_timer_create           = 222
SYS_timer_settime          = 223
SYS_timer_gettime          = 224
SYS_timer_getoverrun       = 225
SYS_timer_delete           = 226
SYS_clock_settime          = 227
SYS_clock_gettime          = 228
SYS_clock_getres           = 229
SYS_clock_nanosleep        = 230
SYS_exit_group             = 231
SYS_epoll_wait             = 232
SYS_epoll_ctl              = 233
SYS_tgkill                 = 234
SYS_utimes                 = 235
SYS_vserver                = 236
SYS_mbind                  = 237
SYS_set_mempolicy          = 238
SYS_get_mempolicy          = 239
SYS_mq_open                = 240
SYS_mq_unlink              = 241
SYS_mq_timedsend           = 242
SYS_mq_timedreceive        = 243
SYS_mq_notify              = 244
SYS_mq_getsetattr          = 245
SYS_kexec_load             = 246
SYS_waitid                 = 247
SYS_add_key                = 248
SYS_request_key            = 249
SYS_keyctl                 = 250
SYS_ioprio_set             = 251
SYS_ioprio_get             = 252
SYS_inotify_init           = 253
SYS_inotify_add_watch      = 254
SYS_inotify_rm_watch       = 255
SYS_migrate_pages          = 256
SYS_openat                 = 257
SYS_mkdirat                = 258
SYS_mknodat                = 259
SYS_fchownat               = 260
SYS_futimesat              = 261
SYS_newfstatat             = 262
SYS_unlinkat               = 263
SYS_renameat               = 264
SYS_linkat                 = 265
SYS_symlinkat              = 266
SYS_readlinkat             = 267
SYS_fchmodat               = 268
SYS_faccessat              = 269
SYS_pselect6               = 270
SYS_ppoll                  = 271
SYS_unshare                = 272
SYS_set_robust_list        = 273
SYS_get_robust_list        = 274
SYS_splice                 = 275
SYS_tee                    = 276
SYS_sync_file_range        = 277
SYS_vmsplice               = 278
SYS_move_pages             = 279
SYS_utimensat              = 280
SYS_epoll_pwait            = 281
SYS_signalfd               = 282
SYS_timerfd                = 283
SYS_eventfd                = 284
SYS_fallocate              = 285
SYS_timerfd_settime        = 286
SYS_timerfd_gettime        = 287
SYS_accept4                = 288
SYS_signalfd4              = 289
SYS_eventfd2               = 290
SYS_epoll_create1          = 291
SYS_dup3                   = 292
SYS_pipe2                  = 293
SYS_inotify_init1          = 294
SYS_preadv                 = 295
SYS_pwritev                = 296
SYS_rt_tgsigqueueinfo      = 297
SYS_perf_event_open        = 298
SYS_recvmmsg               = 299
SYS_fanotify_init          = 300
SYS_fanotify_mark          = 301
SYS_prlimit64              = 302

syscall_names = {
    0: 'read',
    1: 'write',
    2: 'open',
    3: 'close',
    4: 'stat',
    5: 'fstat',
    6: 'lstat',
    7: 'poll',
    8: 'lseek',
    9: 'mmap',
    10: 'mprotect',
    11: 'munmap',
    12: 'brk',
    13: 'rt_sigaction',
    14: 'rt_sigprocmask',
    15: 'rt_sigreturn',
    16: 'ioctl',
    17: 'pread',
    18: 'pwrite',
    19: 'readv',
    20: 'writev',
    21: 'access',
    22: 'pipe',
    23: 'select',
    24: 'sched_yield',
    25: 'mremap',
    26: 'msync',
    27: 'mincore',
    28: 'madvise',
    29: 'shmget',
    30: 'shmat',
    31: 'shmctl',
    32: 'dup',
    33: 'dup2',
    34: 'pause',
    35: 'nanosleep',
    36: 'getitimer',
    37: 'alarm',
    38: 'setitimer',
    39: 'getpid',
    40: 'sendfile',
    41: 'socket',
    42: 'connect',
    43: 'accept',
    44: 'sendto',
    45: 'recvfrom',
    46: 'sendmsg',
    47: 'recvmsg',
    48: 'shutdown',
    49: 'bind',
    50: 'listen',
    51: 'getsockname',
    52: 'getpeername',
    53: 'socketpair',
    54: 'setsockopt',
    55: 'getsockopt',
    56: 'clone',
    57: 'fork',
    58: 'vfork',
    59: 'execve',
    60: 'exit',
    61: 'wait4',
    62: 'kill',
    63: 'uname',
    64: 'semget',
    65: 'semop',
    66: 'semctl',
    67: 'shmdt',
    68: 'msgget',
    69: 'msgsnd',
    70: 'msgrcv',
    71: 'msgctl',
    72: 'fcntl',
    73: 'flock',
    74: 'fsync',
    75: 'fdatasync',
    76: 'truncate',
    77: 'ftruncate',
    78: 'getdents',
    79: 'getcwd',
    80: 'chdir',
    81: 'fchdir',
    82: 'rename',
    83: 'mkdir',
    84: 'rmdir',
    85: 'creat',
    86: 'link',
    87: 'unlink',
    88: 'symlink',
    89: 'readlink',
    90: 'chmod',
    91: 'fchmod',
    92: 'chown',
    93: 'fchown',
    94: 'lchown',
    95: 'umask',
    96: 'gettimeofday',
    97: 'getrlimit',
    98: 'getrusage',
    99: 'sysinfo',
    100: 'times',
    101: 'ptrace',
    102: 'getuid',
    103: 'syslog',
    104: 'getgid',
    105: 'setuid',
    106: 'setgid',
    107: 'geteuid',
    108: 'getegid',
    109: 'setpgid',
    110: 'getppid',
    111: 'getpgrp',
    112: 'setsid',
    113: 'setreuid',
    114: 'setregid',
    115: 'getgroups',
    116: 'setgroups',
    117: 'setresuid',
    118: 'getresuid',
    119: 'setresgid',
    120: 'getresgid',
    121: 'getpgid',
    122: 'setfsuid',
    123: 'setfsgid',
    124: 'getsid',
    125: 'capget',
    126: 'capset',
    127: 'rt_sigpending',
    128: 'rt_sigtimedwait',
    129: 'rt_sigqueueinfo',
    130: 'rt_sigsuspend',
    131: 'sigaltstack',
    132: 'utime',
    133: 'mknod',
    134: 'uselib',
    135: 'personality',
    136: 'ustat',
    137: 'statfs',
    138: 'fstatfs',
    139: 'sysfs',
    140: 'getpriority',
    141: 'setpriority',
    142: 'sched_setparam',
    143: 'sched_getparam',
    144: 'sched_setscheduler',
    145: 'sched_getscheduler',
    146: 'sched_get_priority_max',
    147: 'sched_get_priority_min',
    148: 'sched_rr_get_interval',
    149: 'mlock',
    150: 'munlock',
    151: 'mlockall',
    152: 'munlockall',
    153: 'vhangup',
    154: 'modify_ldt',
    155: 'pivot_root',
    156: '_sysctl',
    157: 'prctl',
    158: 'arch_prctl',
    159: 'adjtimex',
    160: 'setrlimit',
    161: 'chroot',
    162: 'sync',
    163: 'acct',
    164: 'settimeofday',
    165: 'mount',
    166: 'umount2',
    167: 'swapon',
    168: 'swapoff',
    169: 'reboot',
    170: 'sethostname',
    171: 'setdomainname',
    172: 'iopl',
    173: 'ioperm',
    174: 'create_module',
    175: 'init_module',
    176: 'delete_module',
    177: 'get_kernel_syms',
    178: 'query_module',
    179: 'quotactl',
    180: 'nfsservctl',
    181: 'getpmsg',
    182: 'putpmsg',
    183: 'afs_syscall',
    184: 'tuxcall',
    185: 'security',
    186: 'gettid',
    187: 'readahead',
    188: 'setxattr',
    189: 'lsetxattr',
    190: 'fsetxattr',
    191: 'getxattr',
    192: 'lgetxattr',
    193: 'fgetxattr',
    194: 'listxattr',
    195: 'llistxattr',
    196: 'flistxattr',
    197: 'removexattr',
    198: 'lremovexattr',
    199: 'fremovexattr',
    200: 'tkill',
    201: 'time',
    202: 'futex',
    203: 'sched_setaffinity',
    204: 'sched_getaffinity',
    205: 'set_thread_area',
    206: 'io_setup',
    207: 'io_destroy',
    208: 'io_getevents',
    209: 'io_submit',
    210: 'io_cancel',
    211: 'get_thread_area',
    212: 'lookup_dcookie',
    213: 'epoll_create',
    214: 'epoll_ctl_old',
    215: 'epoll_wait_old',
    216: 'remap_file_pages',
    217: 'getdents64',
    218: 'set_tid_address',
    219: 'restart_syscall',
    220: 'semtimedop',
    221: 'fadvise64',
    222: 'timer_create',
    223: 'timer_settime',
    224: 'timer_gettime',
    225: 'timer_getoverrun',
    226: 'timer_delete',
    227: 'clock_settime',
    228: 'clock_gettime',
    229: 'clock_getres',
    230: 'clock_nanosleep',
    231: 'exit_group',
    232: 'epoll_wait',
    233: 'epoll_ctl',
    234: 'tgkill',
    235: 'utimes',
    236: 'vserver',
    237: 'mbind',
    238: 'set_mempolicy',
    239: 'get_mempolicy',
    240: 'mq_open',
    241: 'mq_unlink',
    242: 'mq_timedsend',
    243: 'mq_timedreceive',
    244: 'mq_notify',
    245: 'mq_getsetattr',
    246: 'kexec_load',
    247: 'waitid',
    248: 'add_key',
    249: 'request_key',
    250: 'keyctl',
    251: 'ioprio_set',
    252: 'ioprio_get',
    253: 'inotify_init',
    254: 'inotify_add_watch',
    255: 'inotify_rm_watch',
    256: 'migrate_pages',
    257: 'openat',
    258: 'mkdirat',
    259: 'mknodat',
    260: 'fchownat',
    261: 'futimesat',
    262: 'newfstatat',
    263: 'unlinkat',
    264: 'renameat',
    265: 'linkat',
    266: 'symlinkat',
    267: 'readlinkat',
    268: 'fchmodat',
    269: 'faccessat',
    270: 'pselect6',
    271: 'ppoll',
    272: 'unshare',
    273: 'set_robust_list',
    274: 'get_robust_list',
    275: 'splice',
    276: 'tee',
    277: 'sync_file_range',
    278: 'vmsplice',
    279: 'move_pages',
    280: 'utimensat',
    281: 'epoll_pwait',
    282: 'signalfd',
    283: 'timerfd',
    284: 'eventfd',
    285: 'fallocate',
    286: 'timerfd_settime',
    287: 'timerfd_gettime',
    288: 'accept4',
    289: 'signalfd4',
    290: 'eventfd2',
    291: 'epoll_create1',
    292: 'dup3',
    293: 'pipe2',
    294: 'inotify_init1',
    295: 'preadv',
    296: 'pwritev',
    297: 'rt_tgsigqueueinfo',
    298: 'perf_event_open',
    299: 'recvmmsg',
    300: 'fanotify_init',
    301: 'fanotify_mark',
    302: 'prlimit64',
}
