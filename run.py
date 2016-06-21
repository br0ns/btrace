#!/usr/bin/env python2.7
from btrace import Engine
from ctypes import string_at
import sys
import os

'''
My ad-hoc test bed
'''

class Tracer(object):
    expect_read = False
    # def on_syscall(self, tracee, nr, name, args):
    #     if name in ('exit', 'exit_group'):
    #         args[0] = 42
    #     if name == 'write':
    #         args[2] = 4
    #     print 'syscall', name

    def on_repid(self, tracee, oldpid):
        pass
        # print tracee, 'changed pid from %d to %d' % (oldpid, tracee.pid)

    def on_write(self, tracee, args):
        # print 'write(%d, 0x%x, %d)' % (args[0], args[1], args[2])
        # print 'emulating write, would have printed "%s"' % string_at(args[1])
        # return args[2]
        s = tracee.mem.cstring_at(args[1])
        if 'parent' in s:
            s = s.replace('parent', 'PARENT')
            tracee.mem.put_cstring(args[1], s)

    def on_read_return(self, *_):
        if self.expect_read:
            return 0

    def on_write_return(self, tracee, retval):
        pass
        # print 'retval', retval
        # return max(1, retval - 5)

    def on_death(self, tracee, status):
        if os.WIFSIGNALED(status):
            print 'killed by signal', os.WTERMSIG(status)
        else:
            print 'exited', os.WEXITSTATUS(status)

    def on_signal(self, tracee, signal):
        print 'signal', signal.signo, signal.errno, signal.code, \
            signal.pid, signal.uid

    def on_syscall(self, tracee, *_):
        print 'TGID = %r, TID = %r, PPID = %r' % \
            (tracee.tgid, tracee.tid, tracee.ppid)
        print 'TG = {%s}' % ', '.join(str(t.pid) for t in tracee.thread_group)

    def on_personality_change(self, tracee, _):
        print '[Running in %dbit mode]' % (tracee.wordsize * 8)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        import logging
        logging.basicConfig(level=logging.DEBUG)
        sys.argv.pop(1)

    if len(sys.argv) == 1:
        print 'usage: %s [-v] <program> [<arg> [<arg> ...]]' % sys.argv[0]
        exit(-1)

    tracer = Tracer()
    engine = Engine(tracers = [tracer])

    prog = sys.argv[1]
    args = [prog] + sys.argv[2:]
    engine.start(prog, args)

    # # engine.start('/bin/sh', ['sh'])
    # engine.start('./test/fork.amd64', [''])
    # # engine.start('./test/mmap.amd64', [''])
    # # engine.start('./test/mmap.i386', [''])
