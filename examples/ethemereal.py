#!/usr/bin/env python2.7

# XXX: this doesn't work: python reads the file twice

# Run a program and unlink its file as soon as possible.  This is not trivial in
# the precense of #! since an interpreter will have to read to program.  The
# solution here is:
# - If the target program starts with #! allow exactly one `open`/`openat`.
#   Unlink and detach on `close`.
# - Otherwise unlink and detach after `exec` returns.

import sys
import os
from btrace import Engine

prog = sys.argv[1]
argv = sys.argv[1:]

class Tracer:
    def __init__(self):
        self.fds = {}
        self.fd = None
    def on_open_return(self, tracee, syscall):
        if syscall.retval != 2**(8*tracee.wordsize) - 1:
            # BUG: check for /proc/self/...
            self.fds[syscall.retval] = tracee.mem.cstring_at(syscall.args[0])
    def on_openat_return(self, tracee, syscall):
        AT_FDCWD = 4294967196
        dirfd = syscall.args[0]
        if dirfd == AT_FDCWD:
            path = os.path.join(
                os.readlink('/proc/%d/cwd' % tracee.pid),
                tracee.mem.cstring_at(syscall.args[1])
                )
            if os.path.realpath(prog) == os.path.realpath(path):
                self.fd = syscall.retval
        else:
            # TODO:
            pass
        if syscall.retval != 2**(8*tracee.wordsize) - 1:
            # BUG: check for /proc/self/...
            # print path
            self.fds[syscall.retval] = path

    def on_close(self, tracee, syscall):
        print self.fd, syscall.args[0]
        if syscall.args[0] == self.fd:
            os.unlink(self.fds[self.fd])
        del self.fds[syscall.args[0]]

engine = Engine(tracers=[Tracer()])
engine.start(prog, argv)
