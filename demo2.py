from btrace import Engine

class Tracer:
    tracee = None
    def on_birth(self, tracee):
        if self.tracee:
            self.tracee.detach()
        self.tracee = tracee

    def on_syscall(self, tracee, syscall, args):
        rip = tracee.regs['rip']
        print '[%d] SYS_%s : %#x' % (tracee.pid, syscall.name, syscall.nr)
        print '         CS : %#x' % tracee.regs['cs']
        print '         IP : %#x' % rip
        print '        [IP]: %02x%02x' % (ord(tracee.mem[rip - 2]),
                                          ord(tracee.mem[rip - 1]))

engine = Engine(tracers=[Tracer()])
# engine.start('/bin/bash', ['bash'])
# engine.start('demo64', ['demo64', 'foobar'])
engine.start('a.out', ['a.out'])
