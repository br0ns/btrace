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

class Tracer:
    def on_write(self, tracee, syscall):
        args = syscall.args
        s = tracee.mem.cstring_at(args[1])
        s = s.replace('foo', 'bar')
        tracee.mem.put_cstring(args[1], s)

engine = Engine(tracers = [Tracer()])
engine.start('/bin/sh', ['sh'])
