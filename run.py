#!/usr/bin/env python2.7
from btrace import Engine
from ctypes import *
import sys
import os
import signal

'''
My ad-hoc test bed
'''

steps = 0
def showact(tracee, act, Sigaction):
    if act:
        act = tracee.mem.struct_at(act, Sigaction)
        print '''sigaction {
  .sa_handler   = %s
  .sa_sigaction = %s
  .sa_mask      = %s
  .sa_flags     = %s
  .sa_restorer  = %s
}''' % (hex(act.sa_handler or 0),
        hex(act.sa_sigaction or 0),
        ''.join(map(lambda x: bin(x & 0xff)[2:].ljust(8, '0')[::-1], act.sa_mask)),
        bin(act.sa_flags or 0),
        hex(act.sa_restorer or 0))

class Tracer(object):
    expect_read = False
    # def on_syscall(self, tracee, nr, name, args):
    #     if name in ('exit', 'exit_group'):
    #         args[0] = 42
    #     if name == 'write':
    #         args[2] = 4
    #     print 'syscall', name

    # def on_rt_sigaction(self, tracee, args):
    #     signum = args[0]
    #     act = args[1]
    #     oldact = args[2]
    #     sigsetsize = args[3]
    #     class Sigaction(Structure):
    #         _fields_ = (
    #             ('sa_handler', c_void_p),
    #             ('sa_sigaction', c_void_p),
    #             ('sa_mask', c_byte * sigsetsize),
    #             ('sa_flags', c_int),
    #             ('sa_restorer', c_void_p),
    #         )
    #     print 'rt_sigaction(signum = %d, act = 0x%x, oldact = 0x%x, sigsetsize = %d)' % \
    #         (signum, act, oldact, sigsetsize)
    #     showact(tracee, act, Sigaction)
    #     self.oldact = (tracee, oldact, Sigaction)

    # def on_rt_sigaction_return(self, tracee, retval):
    #     showact(*self.oldact)

    # def on_repid(self, tracee, oldpid):
    #     pass
    #     # print tracee, 'changed pid from %d to %d' % (oldpid, tracee.pid)

    def on_write(self, tracee, args):
        # print 'write(%d, 0x%x, %d)' % (args[0], args[1], args[2])
        # print 'emulating write, would have printed "%s"' % string_at(args[1])
        # return args[2]
        s = tracee.mem.cstring_at(args[1])
        if 'parent' in s:
            s = s.replace('parent', 'PARENT')
            tracee.mem.put_cstring(args[1], s)

    # def on_read_return(self, *_):
    #     if self.expect_read:
    #         return 0

    # # def on_munmap(self, *_):
    # #     self.engine.singlestep = True

    # def on_write_return(self, tracee, retval):
    #     pass
    #     # print 'retval', retval
    #     # return max(1, retval - 5)

    # def on_death(self, tracee, status):
    #     if os.WIFSIGNALED(status):
    #         print 'killed by signal', os.WTERMSIG(status)
    #     else:
    #         print 'exited', os.WEXITSTATUS(status)

    # def on_signal(self, tracee, signal):
    #     print 'signal', signal.signo, signal.errno, signal.code, \
    #         signal.pid, signal.uid

    # def on_syscall(self, tracee, *_):
    #     print 'TGID = %r, TID = %r, PPID = %r' % \
    #         (tracee.tgid, tracee.tid, tracee.ppid)
    #     print 'TG = {%s}' % ', '.join(str(t.pid) for t in tracee.thread_group)

    def on_personality_change(self, tracee, _):
        print '[Running in %dbit mode]' % (tracee.wordsize * 8)

    def on_step(self, tracee, siginfo):
        global steps
        steps += 1
        print 'step', hex(siginfo.addr)

    # def on_signal(self, tracee, siginfo):
    #     if siginfo.signo == signal.SIGUSR1:
    #         return 12

    # forks = 0
    # def on_clone(self, tracee, args):
    #     self.forks += 1
    #     print 'FORKS:', self.forks
    #     if self.forks == 99:
    #         self.engine.follow = True

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        import logging
        logging.basicConfig(level=logging.DEBUG, filename='run.log', filemode='w')
        sys.argv.pop(1)

    if len(sys.argv) == 1:
        print 'usage: %s [-v] <program> [<arg> [<arg> ...]]' % sys.argv[0]
        exit(-1)

    tracer = Tracer()
    engine = Engine(tracers = [tracer])
    # engine.follow = False

    prog = sys.argv[1]
    args = [prog] + sys.argv[2:]
    engine.start(prog, args)
    print steps

    # # engine.start('/bin/sh', ['sh'])
    # engine.start('./test/fork.amd64', [''])
    # # engine.start('./test/mmap.amd64', [''])
    # # engine.start('./test/mmap.i386', [''])
