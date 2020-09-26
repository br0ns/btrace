#!/usr/bin/env python2.7

# Run `sh` but replace 'foo' with 'bar' in any `write()` call:
# $ echo -n f > /tmp/foo
# $ echo oo >> /tmp/foo
# $ ls /tmp
# ...
# bar
# $ cat /tmp/foo
# bar
# $ head -c2 /tmp/foo
# fo

from btrace import Engine
from btrace.tracers import Breakpoints

import logging
logging.basicConfig(level=logging.DEBUG)

main = 0x4004e6
class Tracer(Breakpoints):
    def on_break_0x4004e6(self, tracee):
        print 'breakpoint at main'
    def on_break_0x4004e7(self, tracee):
        print 'breakpoint at main+1'
        # logging.root.level = logging.WARNING
        # tracee.singlestep = True

# class Tracer:
#     def on_write(self, tracee, args):
#         s = tracee.mem.cstring_at(args[1])
#         s = s.replace('foo', 'bar')
#         tracee.mem.put_cstring(args[1], s)

engine = Engine(tracers = [Tracer()])
engine.start('test/hello.amd64', ['hello'])
