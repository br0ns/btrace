from ctypes import *
from ..info import MACHINE as _MACH

class regs_t(Structure):
    if _MACH == 'i386':
        _fields_ = (
            ('ebx'     , c_ulong),
            ('ecx'     , c_ulong),
            ('edx'     , c_ulong),
            ('esi'     , c_ulong),
            ('edi'     , c_ulong),
            ('ebp'     , c_ulong),
            ('eax'     , c_ulong),
            ('ds'      , c_ushort),
            ('__ds'    , c_ushort),
            ('es'      , c_ushort),
            ('__es'    , c_ushort),
            ('fs'      , c_ushort),
            ('__fs'    , c_ushort),
            ('gs'      , c_ushort),
            ('__gs'    , c_ushort),
            ('orig_eax', c_ulong),
            ('eip'     , c_ulong),
            ('cs'      , c_ushort),
            ('__cs'    , c_ushort),
            ('eflags'  , c_ulong),
            ('esp'     , c_ulong),
            ('ss'      , c_ushort),
            ('__ss'    , c_ushort),
            )

    if _MACH == 'amd64':
        _fields_ = (
            ('r15'     , c_ulong),
            ('r14'     , c_ulong),
            ('r13'     , c_ulong),
            ('r12'     , c_ulong),
            ('rbp'     , c_ulong),
            ('rbx'     , c_ulong),
            ('r11'     , c_ulong),
            ('r10'     , c_ulong),
            ('r9'      , c_ulong),
            ('r8'      , c_ulong),
            ('rax'     , c_ulong),
            ('rcx'     , c_ulong),
            ('rdx'     , c_ulong),
            ('rsi'     , c_ulong),
            ('rdi'     , c_ulong),
            ('orig_rax', c_ulong),
            ('rip'     , c_ulong),
            ('cs'      , c_ulong),
            ('eflags'  , c_ulong),
            ('rsp'     , c_ulong),
            ('ss'      , c_ulong),
            ('fs_base' , c_ulong),
            ('gs_base' , c_ulong),
            ('ds'      , c_ulong),
            ('es'      , c_ulong),
            ('fs'      , c_ulong),
            ('gs'      , c_ulong)
            )

pid_t = c_int
uid_t = c_uint
tid_t = c_int
clock_t = c_uint

# From /usr/include/asm-generic/siginfo.h
_SI_PAD_SIZE = 128 - 3 * sizeof(c_int)

class _sigval_t(Union):
    _fields_ = (
        ('int', c_int),
        ('ptr', c_void_p),
    )

class _sifields_kill_t(Structure):
    _fields_ = (
        ('pid', pid_t),
        ('uid', uid_t),
    )

class _sifields_timer_t(Structure):
    _anonymous_ = ('_sigval',)
    _fields_ = (
        ('tid', tid_t),
        ('overrun', c_int),
        ('_sigval', _sigval_t),
    )

class _sifields_rt_t(Structure):
    _anonymous_ = ('_sigval',)
    _fields_ = (
        ('pid', pid_t),
        ('uid', uid_t),
        ('_sigval', _sigval_t),
    )

class _sifields_sigchld_t(Structure):
    _fields_ = (
        ('pid', pid_t),
        ('uid', uid_t),
        ('status', c_int),
        ('utime', clock_t),
        ('stime', clock_t),
    )

class _sifields_sigfault_t(Structure):
    _fields_ = (
        ('addr', c_void_p),
        # XXX: Which architectures use trapno?
        # ('trapno', c_int),
        ('addr_lsb', c_short),
        ('lower', c_void_p),
        ('upper', c_void_p),
    )

class _sifields_sigpoll_t(Structure):
    _fields_ = (
        ('band', c_long),
        ('fd', c_int),
    )

class _sifields_sigsys_t(Structure):
    _fields_ = (
        ('call_addr', c_void_p),
        ('syscall', c_int),
        ('arch', c_uint),
    )

class _sifields_t(Union):
    _anonymous_ = (
        '_kill',
        '_timer',
        '_rt',
        '_sigchld',
        '_sigfault',
        '_sigpoll',
        # '_sigsys',
    )
    _fields_ = (
        ('_pad'     , c_char * _SI_PAD_SIZE),
        ('_kill'    , _sifields_kill_t),
        ('_timer'   , _sifields_timer_t),
        ('_rt'      , _sifields_rt_t),
        ('_sigchld' , _sifields_sigchld_t),
        ('_sigfault', _sifields_sigfault_t),
        ('_sigpoll' , _sifields_sigpoll_t),
        # XXX: Which architectures use SIGSYS?
        # ('_sigsys'  , _sifields_sigsys_t),
    )

class siginfo_t(Structure):
    _anonymous_ = ('_sifields',)
    _fields_ = (
        ('signo', c_int),
        ('errno', c_int),
        ('code', c_int),
        ('_sifields', _sifields_t),
    )
