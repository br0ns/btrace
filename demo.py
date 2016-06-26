from btrace import Engine

class Tracer:
    def on_write(self, tracee, args):
        s = tracee.mem.cstring_at(args[1])
        s = s.replace('foo', 'bar')
        tracee.mem.put_cstring(args[1], s)

engine = Engine(tracers = [Tracer()])
engine.start('/bin/bash', ['bash'])
