import sys
from btrace import Engine

class Tracer:
    def on_ptrace(*_):
        return 0

prog = sys.argv[1]
argv = sys.argv[1:]
engine = Engine(tracers=[Tracer()])
engine.start(prog, argv)
