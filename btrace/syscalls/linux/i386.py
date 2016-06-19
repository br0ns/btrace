NR = ('reg', 'orig_eax')
ARGS = [
    ('reg', 'ebx'),
    ('reg', 'ecx'),
    ('reg', 'edx'),
    ('reg', 'esi'),
    ('reg', 'edi'),
    ('reg', 'ebp'),
]
RETVAL = ('reg', 'eax')

SYS_exit                   =   1
SYS_fork                   =   2
SYS_read                   =   3
SYS_write                  =   4
SYS_open                   =   5
SYS_close                  =   6
SYS_waitpid                =   7
SYS_creat                  =   8
SYS_link                   =   9
SYS_unlink                 =  10
SYS_execve                 =  11
SYS_chdir                  =  12
SYS_time                   =  13
SYS_mknod                  =  14
SYS_chmod                  =  15
SYS_lchown                 =  16
SYS_break                  =  17
SYS_oldstat                =  18
SYS_lseek                  =  19
SYS_getpid                 =  20
SYS_mount                  =  21
SYS_umount                 =  22
SYS_setuid                 =  23
SYS_getuid                 =  24
SYS_stime                  =  25
SYS_ptrace                 =  26
SYS_alarm                  =  27
SYS_oldfstat               =  28
SYS_pause                  =  29
SYS_utime                  =  30
SYS_stty                   =  31
SYS_gtty                   =  32
SYS_access                 =  33
SYS_nice                   =  34
SYS_ftime                  =  35
SYS_sync                   =  36
SYS_kill                   =  37
SYS_rename                 =  38
SYS_mkdir                  =  39
SYS_rmdir                  =  40
SYS_dup                    =  41
SYS_pipe                   =  42
SYS_times                  =  43
SYS_prof                   =  44
SYS_brk                    =  45
SYS_setgid                 =  46
SYS_getgid                 =  47
SYS_signal                 =  48
SYS_geteuid                =  49
SYS_getegid                =  50
SYS_acct                   =  51
SYS_umount2                =  52
SYS_lock                   =  53
SYS_ioctl                  =  54
SYS_fcntl                  =  55
SYS_mpx                    =  56
SYS_setpgid                =  57
SYS_ulimit                 =  58
SYS_oldolduname            =  59
SYS_umask                  =  60
SYS_chroot                 =  61
SYS_ustat                  =  62
SYS_dup2                   =  63
SYS_getppid                =  64
SYS_getpgrp                =  65
SYS_setsid                 =  66
SYS_sigaction              =  67
SYS_sgetmask               =  68
SYS_ssetmask               =  69
SYS_setreuid               =  70
SYS_setregid               =  71
SYS_sigsuspend             =  72
SYS_sigpending             =  73
SYS_sethostname            =  74
SYS_setrlimit              =  75
SYS_getrlimit              =  76
SYS_getrusage              =  77
SYS_gettimeofday           =  78
SYS_settimeofday           =  79
SYS_getgroups              =  80
SYS_setgroups              =  81
SYS_select                 =  82
SYS_symlink                =  83
SYS_oldlstat               =  84
SYS_readlink               =  85
SYS_uselib                 =  86
SYS_swapon                 =  87
SYS_reboot                 =  88
SYS_readdir                =  89
SYS_mmap                   =  90
SYS_munmap                 =  91
SYS_truncate               =  92
SYS_ftruncate              =  93
SYS_fchmod                 =  94
SYS_fchown                 =  95
SYS_getpriority            =  96
SYS_setpriority            =  97
SYS_profil                 =  98
SYS_statfs                 =  99
SYS_fstatfs                = 100
SYS_ioperm                 = 101
SYS_socketcall             = 102
SYS_syslog                 = 103
SYS_setitimer              = 104
SYS_getitimer              = 105
SYS_stat                   = 106
SYS_lstat                  = 107
SYS_fstat                  = 108
SYS_olduname               = 109
SYS_iopl                   = 110
SYS_vhangup                = 111
SYS_idle                   = 112
SYS_vm86old                = 113
SYS_wait4                  = 114
SYS_swapoff                = 115
SYS_sysinfo                = 116
SYS_ipc                    = 117
SYS_fsync                  = 118
SYS_sigreturn              = 119
SYS_clone                  = 120
SYS_setdomainname          = 121
SYS_uname                  = 122
SYS_modify_ldt             = 123
SYS_adjtimex               = 124
SYS_mprotect               = 125
SYS_sigprocmask            = 126
SYS_create_module          = 127
SYS_init_module            = 128
SYS_delete_module          = 129
SYS_get_kernel_syms        = 130
SYS_quotactl               = 131
SYS_getpgid                = 132
SYS_fchdir                 = 133
SYS_bdflush                = 134
SYS_sysfs                  = 135
SYS_personality            = 136
SYS_afs_syscall            = 137
SYS_setfsuid               = 138
SYS_setfsgid               = 139
SYS__llseek                = 140
SYS_getdents               = 141
SYS__newselect             = 142
SYS_flock                  = 143
SYS_msync                  = 144
SYS_readv                  = 145
SYS_writev                 = 146
SYS_getsid                 = 147
SYS_fdatasync              = 148
SYS__sysctl                = 149
SYS_mlock                  = 150
SYS_munlock                = 151
SYS_mlockall               = 152
SYS_munlockall             = 153
SYS_sched_setparam         = 154
SYS_sched_getparam         = 155
SYS_sched_setscheduler     = 156
SYS_sched_getscheduler     = 157
SYS_sched_yield            = 158
SYS_sched_get_priority_max = 159
SYS_sched_get_priority_min = 160
SYS_sched_rr_get_interval  = 161
SYS_nanosleep              = 162
SYS_mremap                 = 163
SYS_setresuid              = 164
SYS_getresuid              = 165
SYS_vm86                   = 166
SYS_query_module           = 167
SYS_poll                   = 168
SYS_nfsservctl             = 169
SYS_setresgid              = 170
SYS_getresgid              = 171
SYS_prctl                  = 172
SYS_rt_sigreturn           = 173
SYS_rt_sigaction           = 174
SYS_rt_sigprocmask         = 175
SYS_rt_sigpending          = 176
SYS_rt_sigtimedwait        = 177
SYS_rt_sigqueueinfo        = 178
SYS_rt_sigsuspend          = 179
SYS_pread                  = 180
SYS_pwrite                 = 181
SYS_chown                  = 182
SYS_getcwd                 = 183
SYS_capget                 = 184
SYS_capset                 = 185
SYS_sigaltstack            = 186
SYS_sendfile               = 187
SYS_getpmsg                = 188
SYS_putpmsg                = 189
SYS_vfork                  = 190
SYS_ugetrlimit             = 191
SYS_mmap2                  = 192
SYS_truncate64             = 193
SYS_ftruncate64            = 194
SYS_stat64                 = 195
SYS_lstat64                = 196
SYS_fstat64                = 197
SYS_lchown32               = 198
SYS_getuid32               = 199
SYS_getgid32               = 200
SYS_geteuid32              = 201
SYS_getegid32              = 202
SYS_setreuid32             = 203
SYS_setregid32             = 204
SYS_getgroups32            = 205
SYS_setgroups32            = 206
SYS_fchown32               = 207
SYS_setresuid32            = 208
SYS_getresuid32            = 209
SYS_setresgid32            = 210
SYS_getresgid32            = 211
SYS_chown32                = 212
SYS_setuid32               = 213
SYS_setgid32               = 214
SYS_setfsuid32             = 215
SYS_setfsgid32             = 216
SYS_pivot_root             = 217
SYS_mincore                = 218
SYS_madvise                = 219
SYS_getdents64             = 220
SYS_fcntl64                = 221


SYS_gettid                 = 224
SYS_readahead              = 225
SYS_setxattr               = 226
SYS_lsetxattr              = 227
SYS_fsetxattr              = 228
SYS_getxattr               = 229
SYS_lgetxattr              = 230
SYS_fgetxattr              = 231
SYS_listxattr              = 232
SYS_llistxattr             = 233
SYS_flistxattr             = 234
SYS_removexattr            = 235
SYS_lremovexattr           = 236
SYS_fremovexattr           = 237
SYS_tkill                  = 238
SYS_sendfile64             = 239
SYS_futex                  = 240
SYS_sched_setaffinity      = 241
SYS_sched_getaffinity      = 242
SYS_set_thread_area        = 243
SYS_get_thread_area        = 244
SYS_io_setup               = 245
SYS_io_destroy             = 246
SYS_io_getevents           = 247
SYS_io_submit              = 248
SYS_io_cancel              = 249
SYS_fadvise64              = 250

SYS_exit_group             = 252
SYS_lookup_dcookie         = 253
SYS_epoll_create           = 254
SYS_epoll_ctl              = 255
SYS_epoll_wait             = 256
SYS_remap_file_pages       = 257
SYS_set_tid_address        = 258
SYS_timer_create           = 259
SYS_timer_settime          = 260
SYS_timer_gettime          = 261
SYS_timer_getoverrun       = 262
SYS_timer_delete           = 263
SYS_clock_settime          = 264
SYS_clock_gettime          = 265
SYS_clock_getres           = 266
SYS_clock_nanosleep        = 267
SYS_statfs64               = 268
SYS_fstatfs64              = 269
SYS_tgkill                 = 270
SYS_utimes                 = 271
SYS_fadvise64_64           = 272
SYS_vserver                = 273
SYS_mbind                  = 274
SYS_get_mempolicy          = 275
SYS_set_mempolicy          = 276
SYS_mq_open                = 277
SYS_mq_unlink              = 278
SYS_mq_timedsend           = 279
SYS_mq_timedreceive        = 280
SYS_mq_notify              = 281
SYS_mq_getsetattr          = 282
SYS_sys_kexec_load         = 283
SYS_waitid                 = 284

SYS_add_key                = 286
SYS_request_key            = 287
SYS_keyctl                 = 288
SYS_ioprio_set             = 289
SYS_ioprio_get             = 290
SYS_inotify_init           = 291
SYS_inotify_add_watch      = 292
SYS_inotify_rm_watch       = 293
SYS_migrate_pages          = 294
SYS_openat                 = 295
SYS_mkdirat                = 296
SYS_mknodat                = 297
SYS_fchownat               = 298
SYS_futimesat              = 299
SYS_fstatat64              = 300
SYS_unlinkat               = 301
SYS_renameat               = 302
SYS_linkat                 = 303
SYS_symlinkat              = 304
SYS_readlinkat             = 305
SYS_fchmodat               = 306
SYS_faccessat              = 307
SYS_pselect6               = 308
SYS_ppoll                  = 309
SYS_unshare                = 310
SYS_set_robust_list        = 311
SYS_get_robust_list        = 312
SYS_splice                 = 313
SYS_sync_file_range        = 314
SYS_tee                    = 315
SYS_vmsplice               = 316
SYS_move_pages             = 317
SYS_getcpu                 = 318
SYS_epoll_pwait            = 319
SYS_utimensat              = 320
SYS_signalfd               = 321
SYS_timerfd                = 322
SYS_eventfd                = 323
SYS_fallocate              = 324
SYS_timerfd_settime        = 325
SYS_timerfd_gettime        = 326
SYS_signalfd4              = 327
SYS_eventfd2               = 328
SYS_epoll_create1          = 329
SYS_dup3                   = 330
SYS_pipe2                  = 331
SYS_inotify_init1          = 332
SYS_preadv                 = 333
SYS_pwritev                = 334
SYS_rt_tgsigqueueinfo      = 335
SYS_perf_event_open        = 336
SYS_recvmmsg               = 337
SYS_fanotify_init          = 338
SYS_fanotify_mark          = 339
SYS_prlimit64              = 340

syscall_names = {
      1: 'exit',
      2: 'fork',
      3: 'read',
      4: 'write',
      5: 'open',
      6: 'close',
      7: 'waitpid',
      8: 'creat',
      9: 'link',
     10: 'unlink',
     11: 'execve',
     12: 'chdir',
     13: 'time',
     14: 'mknod',
     15: 'chmod',
     16: 'lchown',
     17: 'break',
     18: 'oldstat',
     19: 'lseek',
     20: 'getpid',
     21: 'mount',
     22: 'umount',
     23: 'setuid',
     24: 'getuid',
     25: 'stime',
     26: 'ptrace',
     27: 'alarm',
     28: 'oldfstat',
     29: 'pause',
     30: 'utime',
     31: 'stty',
     32: 'gtty',
     33: 'access',
     34: 'nice',
     35: 'ftime',
     36: 'sync',
     37: 'kill',
     38: 'rename',
     39: 'mkdir',
     40: 'rmdir',
     41: 'dup',
     42: 'pipe',
     43: 'times',
     44: 'prof',
     45: 'brk',
     46: 'setgid',
     47: 'getgid',
     48: 'signal',
     49: 'geteuid',
     50: 'getegid',
     51: 'acct',
     52: 'umount2',
     53: 'lock',
     54: 'ioctl',
     55: 'fcntl',
     56: 'mpx',
     57: 'setpgid',
     58: 'ulimit',
     59: 'oldolduname',
     60: 'umask',
     61: 'chroot',
     62: 'ustat',
     63: 'dup2',
     64: 'getppid',
     65: 'getpgrp',
     66: 'setsid',
     67: 'sigaction',
     68: 'sgetmask',
     69: 'ssetmask',
     70: 'setreuid',
     71: 'setregid',
     72: 'sigsuspend',
     73: 'sigpending',
     74: 'sethostname',
     75: 'setrlimit',
     76: 'getrlimit',
     77: 'getrusage',
     78: 'gettimeofday',
     79: 'settimeofday',
     80: 'getgroups',
     81: 'setgroups',
     82: 'select',
     83: 'symlink',
     84: 'oldlstat',
     85: 'readlink',
     86: 'uselib',
     87: 'swapon',
     88: 'reboot',
     89: 'readdir',
     90: 'mmap',
     91: 'munmap',
     92: 'truncate',
     93: 'ftruncate',
     94: 'fchmod',
     95: 'fchown',
     96: 'getpriority',
     97: 'setpriority',
     98: 'profil',
     99: 'statfs',
    100: 'fstatfs',
    101: 'ioperm',
    102: 'socketcall',
    103: 'syslog',
    104: 'setitimer',
    105: 'getitimer',
    106: 'stat',
    107: 'lstat',
    108: 'fstat',
    109: 'olduname',
    110: 'iopl',
    111: 'vhangup',
    112: 'idle',
    113: 'vm86old',
    114: 'wait4',
    115: 'swapoff',
    116: 'sysinfo',
    117: 'ipc',
    118: 'fsync',
    119: 'sigreturn',
    120: 'clone',
    121: 'setdomainname',
    122: 'uname',
    123: 'modify_ldt',
    124: 'adjtimex',
    125: 'mprotect',
    126: 'sigprocmask',
    127: 'create_module',
    128: 'init_module',
    129: 'delete_module',
    130: 'get_kernel_syms',
    131: 'quotactl',
    132: 'getpgid',
    133: 'fchdir',
    134: 'bdflush',
    135: 'sysfs',
    136: 'personality',
    137: 'afs_syscall',
    138: 'setfsuid',
    139: 'setfsgid',
    140: '_llseek',
    141: 'getdents',
    142: '_newselect',
    143: 'flock',
    144: 'msync',
    145: 'readv',
    146: 'writev',
    147: 'getsid',
    148: 'fdatasync',
    149: '_sysctl',
    150: 'mlock',
    151: 'munlock',
    152: 'mlockall',
    153: 'munlockall',
    154: 'sched_setparam',
    155: 'sched_getparam',
    156: 'sched_setscheduler',
    157: 'sched_getscheduler',
    158: 'sched_yield',
    159: 'sched_get_priority_max',
    160: 'sched_get_priority_min',
    161: 'sched_rr_get_interval',
    162: 'nanosleep',
    163: 'mremap',
    164: 'setresuid',
    165: 'getresuid',
    166: 'vm86',
    167: 'query_module',
    168: 'poll',
    169: 'nfsservctl',
    170: 'setresgid',
    171: 'getresgid',
    172: 'prctl',
    173: 'rt_sigreturn',
    174: 'rt_sigaction',
    175: 'rt_sigprocmask',
    176: 'rt_sigpending',
    177: 'rt_sigtimedwait',
    178: 'rt_sigqueueinfo',
    179: 'rt_sigsuspend',
    180: 'pread',
    181: 'pwrite',
    182: 'chown',
    183: 'getcwd',
    184: 'capget',
    185: 'capset',
    186: 'sigaltstack',
    187: 'sendfile',
    188: 'getpmsg',
    189: 'putpmsg',
    190: 'vfork',
    191: 'ugetrlimit',
    192: 'mmap2',
    193: 'truncate64',
    194: 'ftruncate64',
    195: 'stat64',
    196: 'lstat64',
    197: 'fstat64',
    198: 'lchown32',
    199: 'getuid32',
    200: 'getgid32',
    201: 'geteuid32',
    202: 'getegid32',
    203: 'setreuid32',
    204: 'setregid32',
    205: 'getgroups32',
    206: 'setgroups32',
    207: 'fchown32',
    208: 'setresuid32',
    209: 'getresuid32',
    210: 'setresgid32',
    211: 'getresgid32',
    212: 'chown32',
    213: 'setuid32',
    214: 'setgid32',
    215: 'setfsuid32',
    216: 'setfsgid32',
    217: 'pivot_root',
    218: 'mincore',
    219: 'madvise',
    220: 'getdents64',
    221: 'fcntl64',


    224: 'gettid',
    225: 'readahead',
    226: 'setxattr',
    227: 'lsetxattr',
    228: 'fsetxattr',
    229: 'getxattr',
    230: 'lgetxattr',
    231: 'fgetxattr',
    232: 'listxattr',
    233: 'llistxattr',
    234: 'flistxattr',
    235: 'removexattr',
    236: 'lremovexattr',
    237: 'fremovexattr',
    238: 'tkill',
    239: 'sendfile64',
    240: 'futex',
    241: 'sched_setaffinity',
    242: 'sched_getaffinity',
    243: 'set_thread_area',
    244: 'get_thread_area',
    245: 'io_setup',
    246: 'io_destroy',
    247: 'io_getevents',
    248: 'io_submit',
    249: 'io_cancel',
    250: 'fadvise64',

    252: 'exit_group',
    253: 'lookup_dcookie',
    254: 'epoll_create',
    255: 'epoll_ctl',
    256: 'epoll_wait',
    257: 'remap_file_pages',
    258: 'set_tid_address',
    259: 'timer_create',
    260: 'timer_settime',
    261: 'timer_gettime',
    262: 'timer_getoverrun',
    263: 'timer_delete',
    264: 'clock_settime',
    265: 'clock_gettime',
    266: 'clock_getres',
    267: 'clock_nanosleep',
    268: 'statfs64',
    269: 'fstatfs64',
    270: 'tgkill',
    271: 'utimes',
    272: 'fadvise64_64',
    273: 'vserver',
    274: 'mbind',
    275: 'get_mempolicy',
    276: 'set_mempolicy',
    277: 'mq_open',
    278: 'mq_unlink',
    279: 'mq_timedsend',
    280: 'mq_timedreceive',
    281: 'mq_notify',
    282: 'mq_getsetattr',
    283: 'sys_kexec_load',
    284: 'waitid',

    286: 'add_key',
    287: 'request_key',
    288: 'keyctl',
    289: 'ioprio_set',
    290: 'ioprio_get',
    291: 'inotify_init',
    292: 'inotify_add_watch',
    293: 'inotify_rm_watch',
    294: 'migrate_pages',
    295: 'openat',
    296: 'mkdirat',
    297: 'mknodat',
    298: 'fchownat',
    299: 'futimesat',
    300: 'fstatat64',
    301: 'unlinkat',
    302: 'renameat',
    303: 'linkat',
    304: 'symlinkat',
    305: 'readlinkat',
    306: 'fchmodat',
    307: 'faccessat',
    308: 'pselect6',
    309: 'ppoll',
    310: 'unshare',
    311: 'set_robust_list',
    312: 'get_robust_list',
    313: 'splice',
    314: 'sync_file_range',
    315: 'tee',
    316: 'vmsplice',
    317: 'move_pages',
    318: 'getcpu',
    319: 'epoll_pwait',
    320: 'utimensat',
    321: 'signalfd',
    322: 'timerfd',
    323: 'eventfd',
    324: 'fallocate',
    325: 'timerfd_settime',
    326: 'timerfd_gettime',
    327: 'signalfd4',
    328: 'eventfd2',
    329: 'epoll_create1',
    330: 'dup3',
    331: 'pipe2',
    332: 'inotify_init1',
    333: 'preadv',
    334: 'pwritev',
    335: 'rt_tgsigqueueinfo',
    336: 'perf_event_open',
    337: 'recvmmsg',
    338: 'fanotify_init',
    339: 'fanotify_mark',
    340: 'prlimit64',
}
