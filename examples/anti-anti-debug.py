#!/usr/bin/env python2.7

# A common anti-debugging trick is to bail out if `ptrace(TRACEME, ...)` fails,
# because that indicates to the program that a debugger is attached.
#
# This example overrides the return value any `ptrace` syscall with 0 (success).
# $ test/anti-debug.amd64
# Hello, world
# $ bin/run -o /dev/null test/anti-debug.amd64
# NOPE!
# $ examples/anti-anti-debug.py test/anti-debug.amd64
# Hello, world

import sys
from btrace import Engine

class Tracer:
    def on_ptrace(*_):
        return 0

prog = sys.argv[1]
argv = sys.argv[1:]
engine = Engine(tracers=[Tracer()])
engine.start(prog, argv)
