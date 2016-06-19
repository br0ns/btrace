import os

from ctypes import CDLL, addressof, get_errno
from ctypes.util import find_library

from .consts import *
from .structs import *

LIBC_FILENAME = find_library('c')
libc = CDLL(LIBC_FILENAME, use_errno=True)

_ptrace = libc.ptrace
_ptrace.argtypes = (c_ulong,) * 4
_ptrace.restype = c_long

def ptrace(request, pid=0, addr=0, data=0):
    res = _ptrace(request, pid, addr, data)
    if res == -1:
        err = get_errno()
        msg = os.strerror(err)
        raise OSError(err, msg)
    return res

def WPTRACEEVENT(status):
    return status >> 16

def ptrace_traceme():
    ptrace(PTRACE_TRACEME)

def ptrace_peektext(pid, addr):
    return ptrace(PTRACE_PEEKTEXT, pid, addr)
def ptrace_peekdata(pid, addr):
    return ptrace(PTRACE_PEEKDATA, pid, addr)

def ptrace_poketext(pid, addr, data):
    return ptrace(PTRACE_POKETEXT, pid, addr, data)
def ptrace_pokedata(pid, addr, data):
    return ptrace(PTRACE_POKEDATA, pid, addr, data)

# On Linux the `text` and `data` functions are equivalent
def ptrace_peek(pid, addr):
    return ptrace_peekdata(pid, addr)
def ptrace_poke(pid, addr, data):
    ptrace_pokedata(pid, addr, data)

def ptrace_setoptions(pid, opts):
    ptrace(PTRACE_SETOPTIONS, pid, 0, opts)

def ptrace_seize(pid, opts):
    ptrace(PTRACE_SEIZE, pid, 0, opts)

def ptrace_cont(pid, sig=0):
    ptrace(PTRACE_CONT, pid, 0, sig)

def ptrace_syscall(pid, sig=0):
    ptrace(PTRACE_SYSCALL, pid, 0, sig)

def ptrace_sysemu(pid, sig=0):
    ptrace(PTRACE_SYSEMU, pid, 0, sig)

def ptrace_listen(pid):
    ptrace(PTRACE_LISTEN, pid)

def ptrace_interrupt(pid):
    ptrace(PTRACE_INTERRUPT, pid)

def ptrace_getregs(pid):
    regs = regs_t()
    ptrace(PTRACE_GETREGS, pid, 0, addressof(regs))
    return regs

def ptrace_setregs(pid, regs):
    ptrace(PTRACE_SETREGS, pid, 0, addressof(regs))

def ptrace_geteventmsg(pid):
    msg = c_ulong()
    ptrace(PTRACE_GETEVENTMSG, pid, 0, addressof(msg))
    return msg.value

def ptrace_getsiginfo(pid):
    siginfo = siginfo_t()
    ptrace(PTRACE_GETSIGINFO, pid, 0, addressof(siginfo))
    return siginfo

def ptrace_setsiginfo(pid, siginfo):
    ptrace(PTRACE_GETSIGINFO, pid, 0, addressof(siginfo))
