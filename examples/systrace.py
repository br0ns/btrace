#!/usr/bin/env python2
import sys
from btrace import Engine

class Tracer:
    tracee = None
    def on_birth(self, tracee):
        if self.tracee:
            print 'New process PID:%d' % tracee.pid
            print 'Detaching from parent PID:%d' % self.tracee.pid
            self.tracee.detach()
        self.tracee = tracee

    def on_syscall(self, tracee, syscall):
        print '[STOPPED ON SYSCALL]'
        print '  PID = %d' % tracee.pid
        print '  SYS = %s' % syscall.name
        print '  == Registers =='
        print '  RAX = %#x' % tracee.regs['orig_rax']
        print '  RBX = %#x' % tracee.regs['rbx']
        print '  RCX = %#x' % tracee.regs['rcx']
        print '  RDX = %#x' % tracee.regs['rdx']
        print '  RSI = %#x' % tracee.regs['rsi']
        print '  RDI = %#x' % tracee.regs['rdi']
        print '  RBP = %#x' % tracee.regs['rbp']
        print '  RSP = %#x' % tracee.regs['rsp']
        print '  RIP = %#x' % tracee.regs['rip']
        print '  R8  = %#x' % tracee.regs['r8']
        print '  R9  = %#x' % tracee.regs['r9']
        print '  R10 = %#x' % tracee.regs['r10']
        print '  R11 = %#x' % tracee.regs['r11']
        print '  R12 = %#x' % tracee.regs['r12']
        print '  R13 = %#x' % tracee.regs['r13']
        print '  R14 = %#x' % tracee.regs['r14']
        print '  R15 = %#x' % tracee.regs['r15']
        print '  EFLAGS = %#x' % tracee.regs['eflags']
        print

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print 'usage: %s <program> [<arg> [<arg> ...]]' % \
            sys.argv[0]
        exit(-1)

    engine = Engine(tracers=[Tracer()])

    prog = sys.argv[1]
    args = [prog] + sys.argv[2:]
    engine.start(prog, args)
