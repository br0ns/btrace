import os
import errno
import logging
import traceback

from types import MethodType, FunctionType
from collections import defaultdict

from . import callback
from .ptrace   import *
from .signals  import *
from .syscalls import *
from .info     import *
from .tracee   import Tracee

_log = logging.getLogger(__name__)

class Engine(callback.CallbackMixin):
    '''The btrace tracing engine.

    Events:
    - syscall(tracee, syscall, args)
    - syscall_return(tracee, syscall, retval)
    - birth(tracee): after process creation
    - death(tracee, status): before process termination

    - repid(tracee, oldpid)
    - signal(tracee, signal)

    - stop(tracee)
    - cont(tracee)

    - kill(tracee, signum): SIGKILL
    '''
    def __init__(self, follow=True, singlestep=False, tracers=[]):
        self.follow = follow
        self.singlestep = singlestep
        self.tracers = tracers

        self.tracees = {}

        self._callbacks = defaultdict(dict)

        self._ptrace_opts = PTRACE_O_TRACESYSGOOD | \
                            PTRACE_O_EXITKILL     | \
                            PTRACE_O_TRACECLONE   | \
                            PTRACE_O_TRACEFORK    | \
                            PTRACE_O_TRACEVFORK   | \
                            PTRACE_O_TRACEEXEC    | \
                            PTRACE_O_TRACEEXIT

    def start(self, path, argv, envp=None):
        pid = os.fork()
        if pid == 0:
            os.kill(os.getpid(), SIGSTOP)
            # Child
            if envp:
                os.execve(path, argv, envp)
            else:
                os.execv(path, argv)
            # Should not return
            os._exit(0)

        _log.debug('fork() -> %d' % pid)
        ptrace_seize(pid, self._ptrace_opts)
        self._run(pid)

    def attach(self, pid):
        ptrace_seize(pid, self._ptrace_opts)
        ptrace_interrupt(pid)
        self._run(pid)

    def register(self, event, func, **flags):
        self._callbacks[event][func] = flags

    def unregister(self, func):
        for cbs in self._callbacks.values():
            cbs.pop(func, None)

    def _run(self, pid):
        self._new_tracee(pid)

        while self.tracees:
            try:
                pid, status = self._wait()
            except OSError as e:
                if e.errno == errno.ECHILD:
                    _log.debug('no tracees, exiting')
                    break
                raise

            _log.debug('wait() -> %d, %02x|%02x|%02x' % \
                       (pid,
                        status >> 16,
                        (status >> 8) & 0xff,
                        status & 0xff))

            tracee = self.tracees.get(pid)
            if not tracee:
                (_log.warn if self.follow else _log.debug)(
                    '<PID:%d> is not a tracee' % pid)
                continue

            # print 'rdi', hex(tracee.regs.rdi)
            # print 'rsi', hex(tracee.regs.rsi)
            # print 'rdx', hex(tracee.regs.rdx)
            # print 'rcx', hex(tracee.regs.rcx)
            # print 'rax', hex(tracee.regs.rax)
            # print 'r8', hex(tracee.regs.r8)
            # print 'r9', hex(tracee.regs.r9)
            # print 'r10', hex(tracee.regs.r10)
            # print 'r11', hex(tracee.regs.r11)
            # print 'rbx', hex(tracee.regs.rbx)
            # print 'rbp', hex(tracee.regs.rbp)
            # print 'r12', hex(tracee.regs.r12)
            # print 'r13', hex(tracee.regs.r13)
            # print 'r14', hex(tracee.regs.r14)
            # print 'r15', hex(tracee.regs.r15)
            # print 'orig_rax', hex(tracee.regs.orig_rax)

            # Figure out what happened to the tracee
            s = os.WSTOPSIG(status)
            e = WPTRACEEVENT(status)

            # When we continue the tracee, this is the signal we should send it
            cont_signal = 0

            # We are still awaiting the initial stopping of this tracee.  If the
            # tracee was started by btrace it will stop itself and we will
            # observe group-stop, otherwise we will interrupt it or it will
            # automatically stop due to PTRACE_O_{CLONE,FORK,VFORK} and we will
            # observe PTRACE_EVENT_STOP.  In all three cases
            # WPTRACEEVENT(status) will be PTRACE_EVENT_STOP, so we don't need
            # to distinguish between them.
            if tracee._waiting_for_initial_stop:
                if os.WIFSTOPPED(status) and e == PTRACE_EVENT_STOP:
                    _log.debug('seized <PID:%d>' % pid)
                    # We seized the tracee, yay
                    tracee._waiting_for_initial_stop = False
                    ptrace_syscall(pid, 0)
                    continue

                _log.debug('still waiting for <PID:%d>' % pid)
                # If this is not group-stop, event-stop or syscall-stop, then it
                # must be signal-stop
                if not e and not s & 0x80:
                    cont_signal = s

                ptrace_cont(pid, cont_signal)
                continue

            # OK, this is a proper tracee, continue to the real logic

            # Why did wait() return this tracee?
            stopped   = False
            signalled = False
            continued = False
            exited    = False

            # If the tracee was stopped, which kind of stop was it?
            signal_stop  = False
            group_stop   = False
            event_stop   = False
            syscall_stop = False

            # One of these will be set if we have event-stop, signal-stop or
            # termination by signal
            signal = None
            event  = None

            # Tracers can return a value on syscall-enter in which case the
            # syscall is "emulated"
            # XXX: For some reason I couldn't get ptrace_sysemu to work, so I'm
            # XXX: using User-Mode-Linux's trick and replacing it by a syscall
            # XXX: to getpid instead.  See code further down.
            # XXX: Link to UML's SYSEMU patches: http://sysemu.sourceforge.net/
            sysemu = False

            if os.WIFSTOPPED(status):
                stopped = True

                if s == SIGTRAP | 0x80:
                    assert e == 0, \
                        'WPTRACEEVENT(status) should be 0 in syscall-stop'
                    syscall_stop = True

                    if not tracee.in_syscall:
                        # Override syscall number and return value if the
                        # syscall was "emulated", i.e. getpid.  Otherwise read
                        # the syscall from the tracee
                        if tracee.syscall.emulated:
                            tracee.syscall.nr = tracee.syscall.emu_nr
                            tracee.syscall.retval = tracee.syscall.emu_retval
                        else:
                            tracee.syscall._init()

                    syscall = tracee.syscall

                elif e:
                    if s == SIGTRAP:
                        event_stop = True
                        event = e
                    else:
                        assert e == PTRACE_EVENT_STOP, \
                            'WPTRACEEVENT(status) should be ' \
                            'PTRACE_EVENT_STOP in group-stop'
                        group_stop = True

                else:
                    signal_stop = True
                    tracee.signal._init()
                    signal = tracee.signal

            if os.WIFSIGNALED(status):
                signalled = True
                signal = os.WTERMSIG(status)

            if os.WIFCONTINUED(status):
                continued = True

            if os.WIFEXITED(status):
                exited = True
                status = os.WEXITSTATUS(status)

            # Logging
            if stopped:
                reason = 'stopped '
                if signal_stop:
                    reason += '(signal <%d:%s>)' % \
                              (signal.signo, signal_names[signal.signo])
                if group_stop:
                    reason += '(group)'
                if event_stop:
                    reason += '(event <%d:%s>)' % (event, event_names[event])

                if syscall_stop:
                    if tracee.in_syscall:
                        reason += '(syscall-exit <%d:%s> -> 0x%x)' % \
                                  (syscall.nr,
                                   syscall.name,
                                   tracee.syscall.retval)
                    else:
                        reason += '(syscall-enter <%d:%s>)' % \
                                  (syscall.nr, syscall.name)

            if signalled:
                reason = 'signalled (<%d:%s>)' % \
                         (signal, signal_names[signal])

            # This should not happen for a traced process
            if continued:
                reason = 'continued'

            if exited:
                reason = 'exited (%d)' % status

            _log.debug(reason)

            # This tracee was stopped, but now it's running again!
            if not tracee.is_running:
                tracee.is_running = True
                self._run_callbacks('cont', tracee)

            if syscall_stop:
                # On syscall-stop in_syscall will never be set; the idea is that
                # syscall-enter happens strictly before the tracee enters the
                # syscall and syscall-exit strictly after
                if tracee.in_syscall:
                    tracee.in_syscall = False

                    retval = tracee.syscall.retval
                    ret = self._run_callbacks('syscall_return',
                                              tracee, syscall, retval) + \
                          self._run_callbacks(syscall.name + '_return',
                                              tracee, retval)

                    # Reset after callbacks have run so they can see if the
                    # syscall was emulated
                    tracee.syscall.emulated = False

                else:
                    args = tracee.syscall.args
                    ret = self._run_callbacks('syscall',
                                              tracee, syscall, args) + \
                          self._run_callbacks(syscall.name, tracee, args)
                    tracee.in_syscall = True

                # Collect return values
                # XXX: Decide what to do about tracers that write directly to
                # XXX: the syscall object
                ret_ = []
                for f, r in ret:
                    if r == None:
                        continue
                    bits = tracee.wordsize * 8
                    lb = -2**(bits - 1)
                    ub = 2**bits - 1
                    if not isinstance(r, (int, long)) or \
                       r < lb or r > ub:
                        if isinstance(f, MethodType):
                            desc = '%s.%s' % (f.im_class.__name__,
                                              f.im_func.__name__)
                        elif isinstance(f, FunctionType):
                            desc = f.__name__
                        else:
                            desc = repr(f)
                        _log.warn(
                            'callbacks must return an integer [-2^%d;2^%d), ' \
                            '%s returned %r' % (bits - 1, bits, desc, r))
                        continue
                    r &= ub
                    ret_.append(r)
                    func = f
                ret = ret_

                if ret:
                    if len(ret) > 1:
                        _log.warn('multiple syscall return values; last ' \
                                  'callback takes precedence: %r' % func)
                    retval = ret[0]

                    # We were supposed to enter a syscall, but a tracer returned
                    # a value, so we'll "emulate" the syscall instead
                    if tracee.in_syscall:
                        _log.debug('emulating syscall <%d:%s> -> 0x%x' % \
                                   (syscall.nr, syscall.name, retval))

                        # XXX: For some reason ptrace_sysemu doesn't seem to
                        # XXX: work for me, so I replace the syscall with a
                        # XXX: "nop" syscall in the form of getpid
                        tracee.syscall.name = 'getpid'
                        tracee.syscall.emulated = True
                        tracee.syscall.emu_nr = syscall.nr
                        tracee.syscall.emu_retval = retval

                    else:
                        tracee.syscall.retval = retval
                        _log.debug('overriding retval <%d:%s> -> 0x%x' % \
                                   (syscall.nr, syscall.name, retval))

                # If we are about to enter a clone syscall and want to follow
                # the child, then make sure that the CLONE_UNTRACED flag is not
                # set.  We need to do it here, after the callbacks have run as
                # the syscall may be simluted.  CLONE_UNTRACED is defined in
                # /usr/include/linux/sched.h
                CLONE_UNTRACED = 0x00800000
                if self.follow              and \
                   tracee.in_syscall        and \
                   not syscall.emulated     and \
                   syscall.name == 'clone'  and \
                   syscall.args[0] & CLONE_UNTRACED:
                    syscall.args[0] &= ~CLONE_UNTRACED
                    _log.debug('removed CLONE_UNTRACED flag in clone syscall')

            # Run callbacks for on signal and group-stop
            elif signal_stop:
                # XXX: Let callbacks decide to suppress the signal
                self._run_callbacks('signal', tracee, signal)
                # Since a callback may have changed the signal we cannot know
                # the signal to restart the tracee with until now
                cont_signal = signal.signo
            elif group_stop:
                tracee.is_running = False
                self._run_callbacks('stop', tracee)

            # Handle births
            elif event in (PTRACE_EVENT_FORK,
                           PTRACE_EVENT_VFORK,
                           PTRACE_EVENT_CLONE):
                newpid = ptrace_geteventmsg(pid)
                self._new_tracee(newpid)

            # Handle deaths
            elif event == PTRACE_EVENT_EXIT:
                status = ptrace_geteventmsg(pid)
                self._run_callbacks('death', tracee, status)

            # Handle exec's: when a thread which is not the thread group leader
            # executes execve, all other threads in the thread group die and the
            # execve'ing thread becomes leader
            elif event == PTRACE_EVENT_EXEC:
                # TODO: write this
                pass

            # Tracee exited or was killed by a signal, so remove it.  No need to
            # report this exit as we have already done so when we got
            # PTRACE_EVENT_EXIT
            # Caveat: At the moment (kernel 4.5.0) tracees stop in event-stop
            #   with PTRACE_EVENT_EXIT even if they are killed by SIGKILL.
            #   According to the man page that may change in the future.  We
            #   handle that hypothetical situation below, if ptrace fails with
            #   ESRCH
            elif exited or signalled:
                del self.tracees[pid]
                continue

            # Write-back and reset register, memory and siginfo caches
            tracee._writeback()

            # Continue the tracee
            try:
                if group_stop:
                    _log.debug('<PID:%d> stopped, calling ptrace_listen' % \
                               pid)
                    ptrace_listen(pid)
                elif sysemu:
                    # XXX: See comments about ptrace_sysemu above
                    ptrace_sysemu(pid, cont_signal)
                else:
                    ptrace_syscall(pid, cont_signal)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    # This doesn't happen at the moment (kernel 4.5.0), but it
                    # may in the future.  See the BUGS section in the ptrace man
                    # page.
                    del self.tracees[pid]
                    self._run_callbacks('kill', tracee)
                else:
                    raise

    def _wait(self):
        while True:
            try:
                # From /usr/include/linux/wait.h
                __WALL = 0x40000000
                return os.waitpid(-1, __WALL)
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                raise

    def _run_callbacks(self, event, *args, **kwargs):
        out = []

        def run(func):
            if not func:
                return
            try:
                ret = func(*args, **kwargs)
                if ret != None:
                    out.append((func, ret))
            except Exception as e:
                _log.error('Callback for event "%s" raised an exception: %r' % \
                           (event, e))
                _log.debug('Traceback:\n' + traceback.format_exc())

        for tracer in self.tracers:
            run(getattr(tracer, 'on_' + event, None))

        for func, flags in self._callbacks[event].items():
            if flags.get('once'):
                del callbacks[func]
            run(func)

        return out

    def _new_tracee(self, pid):
        tracee = Tracee(pid)
        assert pid not in self.tracees, \
            '<PID:%d> is already a tracee' % pid
        self.tracees[pid] = tracee
        self._run_callbacks('birth', tracee)
