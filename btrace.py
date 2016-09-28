#!/usr/bin/env python2.7
import logging
import sys

from btrace import Engine

if __name__ == '__main__':
    if sys.argv[1] == '-o' and len(sys.argv) > 3:
        sys.argv.pop(1)
        logfile = sys.argv.pop(1)
        logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='w')
    else:
        logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) == 1:
        print 'usage: %s [-o <logfile>] <program> [<arg> [<arg> ...]]' % \
            sys.argv[0]
        exit(-1)

    engine = Engine(trace_restart=True)

    prog = sys.argv[1]
    args = [prog] + sys.argv[2:]
    engine.start(prog, args)
