__all__ = (
    'Breakpoints',
)

from collections import defaultdict
from elftools.elf.elffile import ELFFile

from btrace.info import ARCH, REG_SP, REG_PC

if ARCH in ('i386', 'amd64'):
    _BP_OPCODE = '\xcc'

# Sentinels for location base
class Zero(object):
    pass
class Load(object):
    pass
class BP(object):
    def __init__(self, loc, cb):
        self.addr = 0
        self.base = Zero
        self.tail = False # Relative to end of symbol
        self.hook = cb
        if isinstance(loc, (int, long)):
            self.addr = loc
        elif loc[0] == '+':
            self.addr = int(loc[1:], 0)
            self.base = Load
        elif loc[0] == '<':
            i = loc.rindex('>')
            self.base = loc[1:i]
            i += 1
            if loc[i] == '!':
                self.tail = True
                i += 1
            self.addr = int(loc[i:], 0)
        else:
            self.addr = int(loc, 0)

class Breakpoints(object):
    def __init__(self):
        self._reinsert = {}
        # Active breakpoints
        #   tracee -> {addr: (orig, [hook])}
        self._bs = defaultdict(dict)

        # Deferred breakpoints; e.g. a library hasn't been loaded yet
        #   tracee -> {breakpoint}
        self._ds = defaultdict(set)

        # Global breakpoints should be added to tracees on birth
        #   {breakpoint}
        self._gs = set()

        # Is set by btrace.Engine
        self.engine = None

        # Add breakpoints for callbacks defined as methods
        for name in dir(self):
            if name.startswith('on_break_'):
                loc = name[9:]
                hook = getattr(self, name)
                self.add(loc, hook)

    # Private methods

    def _resolve(self, tracee, bp):
        if bp.base != Zero:
            raise NotImplementedError()
        return bp.addr

    def _set(self, tracee, bp):
        addr = self._resolve(tracee, bp)
        if addr is None:
            # XXX: emit warning
            self._ds[tracee].add(bp)
            return
        try:
            if addr not in self._bs[tracee]:
                self._bs[tracee][addr] = (tracee.mem[addr], [])
                tracee.mem[addr] = _BP_OPCODE
            self._bs[tracee][addr][1].append(bp.hook)
        except OSError:
            # XXX: emit warning
            self._ds[tracee].add(bp)

    # Public methods

    def add(self, loc, callback=None, tracee=None):
        try:
            bp = BP(loc, callback)
        except:
            raise ValueError('invalid location format: %s' % loc)

        if tracee:
            assert tracee.engine == self.engine
            tracees = {tracee}
        else:
            self._gs.add(bp)
            if self.engine:
                for tracee in self.engine.tracees:
                    self._set(tracee, bp)

    def remove(self, loc, callback=None, tracee=None):
        raise NotImplementedError()

    # Callbacks

    def on_birth(self, tracee):
        for bp in self._gs:
            self._set(tracee, bp)

    def on_death(self, tracee, _status):
        # Cleanup
        try:
            del self._bs[tracee]
        except:
            pass
        try:
            del self._ds[tracee]
        except:
            pass

    def on_TRAP(self, tracee, _siginfo):
        print 'trapped'
        # Optimization: No breakpoints, no need to read PC
        if tracee not in self._bs:
            return
        pc = tracee.regs[REG_PC] - len(_BP_OPCODE)
        # Not at a breakpoint
        if pc not in self._bs[tracee]:
            return
        orig, hooks = self._bs[tracee][pc]
        print orig.encode('hex')
        tracee.mem[pc] = orig
        for hook in hooks:
            hook(tracee)
        # XXX: allow hooks to remove breakpoints, and in that case don't write a
        #      BP back in mem.  Also mark cache as not dirty if nothing changed
        tracee.regs[REG_PC] = pc
        print tracee.mem[pc:pc+5].encode('hex')
        tracee.singlesteps += 1
        self._reinsert[tracee] = pc
        # Don't send TRAP to process
        return 0

    def on_step(self, tracee):
        print 'stepped', tracee
        exit()
        pass

    def on_SEGV(self, tracee, siginfo):
        print tracee.regs
