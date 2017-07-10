# coding: utf-8

import os
import errno
import logging
import traceback
import types
import ctypes

from collections import defaultdict

from .ptrace      import *
from .tracee      import Tracee
from .personality import personality
from .signals     import signal_names, SIGSTOP, SIGCONT, SIGTRAP
# These are the tracer's syscalls, not the tracee's.
from .info        import SYSCALLS

_log = logging.getLogger(__name__)
_debug = _log.debug

# Python (or libc for that matter) does not expose the `tgkill` syscall, so we
# must create it ourselves.
_libc = ctypes.CDLL(ctypes.util.find_library('c'))
def _tgkill(tgid, tid, sig):
    _libc.syscall(SYSCALLS.SYS_tgkill, tgid, tid, sig)

# Utility function that returns a functions' name.
def _funcdesc(f):
    '''Internal utility function'''
    if isinstance(f, types.MethodType):
        return '%s.%s' % (f.im_class.__name__,
                          f.im_func.__name__)
    elif isinstance(f, types.FunctionType):
        return f.__name__
    else:
        return repr(f)

# "Alias" for ptrace options to follow all children.  If a tracee calls `clone`
# with the `PTRACE_VFORK` flag we will observe `PTRACE_EVENT_VFORK` (if
# `PTRACE_O_TRACEFORK` is set), if `clone` is called with exit signal `SIGCHLD`
# then `PTRACE_EVENT_FORK` is observed (if `PTRACE_O_FORK` is set), and in all
# other cases `PTRACE_EVENT_CLONE` is observed (if `PTRACE_O_CLONE` is set).
PTRACE_O_FOLLOW = \
    PTRACE_O_TRACECLONE   | \
    PTRACE_O_TRACEFORK    | \
    PTRACE_O_TRACEVFORK

# Corresponding "alias" for events.
PTRACE_EVENTS_FOLLOW = (
    PTRACE_EVENT_CLONE,
    PTRACE_EVENT_FORK,
    PTRACE_EVENT_VFORK)

# A syscall returning one of these values will be restarted.  Defined in:
#   /include/linux/errno.h.  See also /linux/arch/um/kernel/signal.c.
ERESTARTSYS           = 0x200
ERESTARTNOINTR        = 0x201
ERESTARTNOHAND        = 0x202
ERESTART_RESTARTBLOCK = 0x204
RETVAL_RESTART = (
    -ERESTARTSYS,
    -ERESTARTNOINTR,
    -ERESTARTNOHAND,
    -ERESTART_RESTARTBLOCK)

class Engine(object):
    '''The Btrace tracing engine.

    The tracing engine monitors a collection of :class:`tracee.Tracee`s.  A list
    of tracers recieve callbacks for various events.  See
    :class:`tracers.DocTracer` for details on the tracer API.
    '''
    def __init__(self, tracers=[], follow=True, singlestep=False,
                 trace_restart=False):
        '''__init__(tracers = [], follow = True, singlestep = False,
                                trace_restart = False) -> Engine

        Arguments:
            tracers(iterable): Tracers receiving callbacks from the tracing engine.
                Tracers can be added and removed by manipulating the list
                :attr:`tracers`.  No tracers are enabled by default.
            follow(bool): Attach to children (and clones) as they are created.  Can be
                changed by setting :attr:`follow`.  Enabled by default.
            singlestep(bool): Singlestep all attached tracees (*very* slow).  Can be
                changed by setting :attr:`singlestep`.  Disabled by default.
            trace_restart(bool): Invoke callbacks for restarted syscalls.  Can be
                changed by setting :attr:`trace_restart`.  Disabled by default.
        '''
        self.singlestep = singlestep
        self.trace_restart = trace_restart
        self.tracers = list(tracers)

        self.tracees = {}

        # Dictionary of ad-hoc callbacks: event -> function -> flags
        self._callbacks = defaultdict(dict)

        opts = PTRACE_O_TRACESYSGOOD | \
               PTRACE_O_EXITKILL     | \
               PTRACE_O_TRACEEXEC    | \
               PTRACE_O_TRACEEXIT

        if follow:
            opts |= PTRACE_O_FOLLOW

        self._ptrace_opts = opts
        self._follow = follow

    @property
    def follow(self):
        return self._follow

    @follow.setter
    def follow(self, follow):
        if follow == self._follow:
            return
        self._follow = follow
        if follow:
            _debug('enabling follow mode')
            self._ptrace_opts |= PTRACE_O_FOLLOW
        else:
            _debug('disabling follow mode')
            self._ptrace_opts &= ~PTRACE_O_FOLLOW

        for pid in self.tracees.keys():
            ptrace_setoptions(pid, self._ptrace_opts)

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

        _debug('fork() -> %d' % pid)
        ptrace_seize(pid, self._ptrace_opts)
        self._run(pid)

    def attach(self, pid):
        ptrace_seize(pid, self._ptrace_opts)
        ptrace_interrupt(pid)
        self._run(pid)

    def detach(self, pid_or_tracee):
        if isinstance(pid_or_tracee, (int, long)):
            pid = pid_or_tracee
            tracee = self.tracees.get(pid)
            if not tracee:
                raise ValueError('no tracee with PID=%d' % pid)
        else:
            tracee = pid_or_tracee
        tracee.detach()

    def register(self, event, func, **flags):
        self._callbacks[event][func] = flags

    def unregister(self, func):
        for cbs in self._callbacks.values():
            cbs.pop(func, None)

    def _run(self, pid):
        # This is the entry point after running either `start` or `attach`.  In
        # both cases we are already the tracer of `pid`, and the process is
        # running.

        # The initial tracee is the only tracee that may stop for other reasons
        # before `PTRACE_EVENT_STOP`, so we handle it specially here.  If the
        # tracee was created with `Engine.start` then it will stop itself with
        # `SIGSTOP`, in which case we will observe group-stop.  But
        # `WPTRACEEVENT(status) will also be `PTRACE_EVENT_STOP` in that case,
        # so there's no reason to distinguish between them.
        while True:
            pid_, status = self._wait()
            if pid != pid_:
                _debug('child <PID:%d> is not initial tracee' % pid_)
                continue

            e = WPTRACEEVENT(status)
            s = os.WSTOPSIG(status)
            if os.WIFSTOPPED(status) and e == PTRACE_EVENT_STOP:
                _debug('seized initial tracee <PID:%d>' % pid)
                self._new_tracee(pid)
                break

            _debug('still waiting for <PID:%d>' % pid)
            # If this is not group-stop (`e` != 0 and `s` != `SIGTRAP`),
            # event-stop (`e` != 0 and `s` == `SIGTRAP`) or syscall-stop (`s` &
            # 0x80), then it must be signal-stop.
            if not e and not s & 0x80:
                cont_signal = s
            else:
                cont_signal = 0

            ptrace_cont(pid, cont_signal)
            continue

        # For a child to become a tracee two things must happen: 1)
        # `PTRACE_EVENT_STOP` is observed in the child and 2)
        # `PTRACE_EVENT_{FORK,VFORK,CLONE}`is observed in the parent.  The first
        # condition ensures that the tracee is running and the second lets us
        # know the parent.
        #
        # In the case of the `clone` syscall we must also save the flags used,
        # as they decide the thread group and parent of the child.
        #
        # Caveat: I have only seen `PTRACE_EVENT_STOP` before
        #   `PTRACE_EVENT_{FORK,VFORK,CLONE}` in the case of `vfork`, and not
        #   consistently, but the ptrace man page doesn't say anything about the
        #   order.  Besides, there's no reason to rely on it anyway.

        # `stop_seen` records the children in whom we have observed
        # `PTRACE_EVENT_STOP`.
        stop_seen = set()

        # `parent_seen` maps children to their "parents".  Here parent refers to
        # the process that spawned the child, not the childs parent as reported
        # by `getppid`.
        parent_seen = {}

        # `clone_flags` maps parents to the flags used in the `clone` syscall.
        # When `clone` is called the PID of the child is not yet known, so the
        # mapping cannot be from children.
        clone_flags = {}

        # This function creates a tracee if the conditions discussed above are
        # met.
        def maybe_tracee(pid):
            if pid not in stop_seen:
                _debug('PTRACE_EVENT_STOP has not yet been observed in '
                       '<PID:%d>' % pid)
                return
            if pid not in parent_seen:
                _debug('parent of <PID:%d> has not yet observed '
                       'PTRACE_EVENT_{FORK,VFORK,CLONE}' % pid)
                return
            parent = parent_seen.pop(pid)
            cflags = clone_flags.pop(parent.pid, 0)
            self._new_tracee(pid, parent, cflags)

        while self.tracees or True:
            try:
                pid, status = self._wait()
            except OSError as e:
                if e.errno == errno.ECHILD:
                    # This may happen if all the tracees are killed by SIGKILL,
                    # so we didn't get a change to observe their death.
                    _debug('no children, exiting')
                    break
                raise

            _debug('wait() -> %d, %02x|%02x|%02x' % \
                   (pid,
                    status >> 16,
                    (status >> 8) & 0xff,
                    status & 0xff))

            if pid not in self.tracees:
                # The child is not a tracee.  That can happen because 1) it was
                # created with follow mode disabled, and is not meant to be a
                # tracee, or 2) this is the first time we see the tracee in
                # which case we expect observe `PTRACE_EVENT_STOP`

                # According to the `wait(2)` man page `WIFSTOPPED(status)` can
                # only be true if `wait` was called with `UNTRACED` or if the
                # child is a ptrace tracee.  In the second case we must observe
                # `PTRACE_EVENT_STOP`.
                if os.WIFSTOPPED(status):
                    assert WPTRACEEVENT(status) == PTRACE_EVENT_STOP, \
                        'non-tracee child stopped without PTRACE_EVENT_STOP'
                    assert pid not in stop_seen, \
                        'already saw PTRACE_EVENT_STOP for child <PID:%d>' % pid
                    stop_seen.add(pid)
                    # Create and start tracee if we already know the parent
                    maybe_tracee(pid)
                continue

            # OK, this is a proper tracee, continue to the real logic.  First we
            # figure out what happened to it.
            tracee = self.tracees.get(pid)

            s = os.WSTOPSIG(status)
            e = WPTRACEEVENT(status)

            # When we continue the tracee, this is the signal we should send it
            cont_signal = 0

            # Why did `wait` return this tracee?
            stopped   = False
            signalled = False
            continued = False
            exited    = False

            # If the tracee was stopped, which kind of stop was it?
            signal_stop  = False
            group_stop   = False
            event_stop   = False
            syscall_stop = False

            # This will be sent if we have event-stop
            event  = None

            # Tracers can return a value on syscall-enter in which case the
            # syscall is "emulated"
            # XXX: For some reason I couldn't get ptrace_sysemu to work, so I'm
            # XXX: using User-Mode-Linux's trick and replacing it by a syscall
            # XXX: to getpid instead.  See code further down.
            # XXX: Link to UML's SYSEMU patches: http://sysemu.sourceforge.net/
            sysemu = False

            # Here we just set the variables.  The real logic follows below.
            if os.WIFSTOPPED(status):
                stopped = True

                if s == SIGTRAP | 0x80:
                    assert e == 0, \
                        'WPTRACEEVENT(status) should be 0 in syscall-stop'
                    syscall_stop = True
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
                    tracee.siginfo._init()
                    siginfo = tracee.siginfo
                    cont_signal = s

            if os.WIFSIGNALED(status):
                signalled = True
                signal = os.WTERMSIG(status)

            if os.WIFCONTINUED(status):
                continued = True

            if os.WIFEXITED(status):
                exited = True
                status = os.WEXITSTATUS(status)

            # Tracee exited or was killed by a signal, so remove it.  No need to
            # report this exit as we have already done so when we got
            # `PTRACE_EVENT_EXIT`.
            #
            # Caveat: At the moment (kernel 4.5.0) tracees stop in event-stop
            #   with `PTRACE_EVENT_EXIT` even if they are killed by `SIGKILL`.
            #   According to the man page that may change in the future.  We
            #   handle that hypothetical situation below, if ptrace fails with
            #   `ESRCH` when we continue the tracee.
            if exited or signalled:
                _debug('<PID:%d> terminated' % pid)
                self._del_tracee(tracee)
                continue

            # Log events.
            if event:
                _debug('event %d:%s' % (event, event_names[event]))

            # Handle `execve`'s: when a thread which is not the thread group
            # leader executes `execve`, all other threads in the thread group
            # die and the `execve`'ing thread becomes leader.  This code must be
            # executed early as `tracee` is in fact the wrong tracee at this
            # point, and we need to correct that.
            if event == PTRACE_EVENT_EXEC:
                oldpid = ptrace_geteventmsg(pid)
                if pid != oldpid:
                    _debug('repid (%d -> %d)' % (oldpid, pid))
                    # Neither this tracee nor the thread group leader will
                    # report death, so we must do the clean-up here
                    self._del_tracee(tracee)
                    # This is the correct tracee, it just changed its pid
                    tracee = self.tracees.pop(oldpid)
                    tracee.pid = pid
                    tracee.thread_group = set([tracee])
                    tracee.tgid = tracee.pid
                    self.tracees[pid] = tracee
                    self._run_callbacks('repid', tracee, oldpid)

            # We're entering or exiting a syscall so update `in_syscall`.
            # Invariant: a callback for `syscall` will always see `in_syscall`
            # as being true, and a callback for `syscall_return` will always see
            # it as being false.
            #
            # This check must be placed here, before the personality is
            # detected, because a syscall on Linux x86_64 (XXX: and others?) be
            # run in 32 bit mode depending on how it was called (specifically
            # through `int 0x80` or 32 bit `syscall` [which apparently only
            # exists on AMD CPU's and is all but undocumented; see comment in
            # `/linux/arch/x86/entry/entry_32.S`]).
            if syscall_stop:
                # Go from syscall to not in syscall or vice versa
                tracee.in_syscall ^= True

            # See if the tracee changed personality.  This check may depend on
            # `in_syscall` (see comment above).
            self._detect_personality(tracee)

            # OK, now all the tracee's state variables has been set and we're
            # ready to fire callbacks, etc.

            # Trigger single step callbacks.  We do not reset
            # `_was_singlestepped` here because we need it to be set in order to
            # supress callbacks for `SIGTRAP`.
            if tracee._was_singlestepped:
                _debug('step')
                self._run_callbacks('step', tracee)

            # This tracee was stopped, but now it's running again!
            if not tracee.is_running:
                tracee.is_running = True
                self._run_callbacks('cont', tracee)

            # Handle syscalls.
            if syscall_stop:

                # This is syscall-enter.
                if tracee.in_syscall:
                    # The `nr` and `name` attributes are what the tracer sees
                    # and not the real values in case of a restarted or emulated
                    # syscall.
                    realnr = syscall._get_nr()
                    realname = tracee.syscalls.syscall_names[realnr]

                    _debug('syscal-enter %d:%s' % (realnr, realname))

                    if self.trace_restart or realname != 'restart_syscall':
                        # Initialize syscall object.
                        syscall._init()

                        args = syscall.args
                        retval = self._run_syscall_callbacks(tracee)

                        # We were supposed to enter a syscall, but a tracer
                        # returned a value, so we'll "emulate" the syscall
                        # instead.
                        if retval != None:
                            _debug('emulating syscall %d:%s -> 0x%x' % \
                                   (syscall.nr, syscall.name, retval))
                            # XXX: For some reason `ptrace_sysemu` doesn't seem
                            # XXX: to work for me, so I replace the syscall with
                            # XXX: a "nop" syscall in the form of `getpid`
                            syscall.emulated = True
                            syscall.emu_nr = syscall.nr
                            syscall.emu_retval = retval
                            syscall.name = 'getpid'

                        # We are about to enter an un-emulated (if it was
                        # emulated `name` would be "getpid") `clone` syscall and
                        # we want to follow the child.  We must save the flags
                        # used in the syscall so we can correctly set the parent
                        # and thread group of the newly created process/thread
                        # when it arrives.  Also, if the `CLONE_UNTRACED` flag
                        # is set, we unset it so we become a tracer of the
                        # child.  This check needs to be placed here, after the
                        # callbacks have run, as the syscall may be changed or
                        # simulated by a tracer.  `CLONE_UNTRACED` is defined in
                        # /usr/include/linux/sched.h
                        CLONE_UNTRACED = 0x00800000
                        if self.follow and syscall.name == 'clone':
                            if syscall.args[0] & CLONE_UNTRACED:
                                _debug('removed CLONE_UNTRACED in clone ' \
                                       'syscall')

                            clone_flags[pid] = syscall.args[0]
                            syscall.args[0] &= ~CLONE_UNTRACED

                    else:
                        _debug('ignoring syscall-enter due to restart')

                # This is syscall-exit.
                else:
                    _debug('syscall-exit %d:%s -> %#x' % \
                           (syscall.nr, syscall.name, syscall.retval))

                    if self.trace_restart or \
                       syscall.retval not in RETVAL_RESTART:
                        # Finalize syscall object, i.e. stop the timer.
                        syscall._fini()

                        # Set syscall number and return value if the syscall was
                        # "emulated", i.e. `getpid`.
                        if syscall.emulated:
                            syscall.nr = syscall.emu_nr
                            syscall.retval = syscall.emu_retval

                        retval = self._run_syscall_callbacks(tracee)

                        if retval != None:
                            _debug('overriding syscall %d:%s -> 0x%x' % \
                                   (syscall.nr, syscall.name, retval))

                            syscall.retval = retval

                        # The `emulated` flag is reset here, after the callbacks
                        # have run, so they can see whether the syscall was
                        # emulated or not.
                        syscall.emulated = False

                    else:
                        _debug('ignoring syscall-exit due to restart')

            # Run callbacks for signals and single stepping.
            elif signal_stop:
                # A single stepped tracee will signal-stop with `SIGTRAP` when
                # executing the next instruction, so we need to supress that
                # signal.  Otherwise run callbacks and deliver signals as usual.
                if siginfo.signo == SIGTRAP and tracee._was_singlestepped:
                    cont_signal = 0

                else:
                    _debug('signal %d:%s' % (siginfo.signo, siginfo.signame))

                    retval = self._run_signal_callbacks(tracee)
                    if retval != None:
                        if retval == 0:
                            _debug('supressing signal %d:%s' % \
                                   (siginfo.signo, siginfo.signame))
                        else:
                            _debug('overriding signal %d:%s -> %d:%s' % \
                                   (siginfo.signo, siginfo.signame, retval,
                                    signal_names.get(retval, 'SIG???')))

                        cont_signal = retval

            # Ditto for group-stops.
            elif group_stop:
                _debug('group-stop')

                tracee.is_running = False
                self._run_callbacks('stop', tracee)

            # Handle births.
            elif event in PTRACE_EVENTS_FOLLOW:
                newpid = ptrace_geteventmsg(pid)

                # Even if the child is not the result of a `clone` syscall, we
                # may have saved clone flags if a previous `clone` failed.  In
                # that case we must remove the stale flags.
                if event != PTRACE_EVENT_CLONE:
                    clone_flags.pop(pid, None)

                # Record this tracee as the parent.
                parent_seen[newpid] = tracee

                # And finally create and start the new tracee if
                # `PTRACE_EVENT_STOP` was already seen (as mentioned above, I've
                # only seen this behavior from `vfork`).
                maybe_tracee(newpid)

            # Handle deaths.
            elif event == PTRACE_EVENT_EXIT:
                status = ptrace_geteventmsg(pid)
                tracee.is_running = False
                tracee.is_alive = False
                self._run_callbacks('death', tracee, status)

            # Should the tracee be single stepped?
            do_singlestep = self.singlestep or tracee.singlestep or \
                            tracee.singlesteps > 0
            # If so, we need a to know whether we're about to make a syscall or
            # not, and figuring that out probably requires reading the tracee's
            # registers and/or memory, so we should do it here, before we flush
            # the register, memory and siginfo caches.
            if do_singlestep:
                at_syscall = tracee.at_syscall

            # And now we can flush them.
            tracee._cacheflush()

            # Continue the tracee.
            try:
                if group_stop:
                    ptrace_listen(pid)

                elif sysemu:
                    # XXX: See comments about `ptrace_sysemu` above.
                    ptrace_sysemu(pid, cont_signal)

                elif tracee._do_detach:
                    _debug('detached <PID:%d>' % pid)
                    ptrace_detach(pid, cont_signal)
                    # Continue the tracee.
                    _tgkill(tracee.tgid, tracee.tid, SIGCONT)

                elif do_singlestep:
                    # For each tracee we record whether it was single stepped
                    # since any of the variables above may change before we
                    # observe SIGTRAP and thus cannot be relied on
                    tracee._was_singlestepped = True

                    # We decrement `singlesteps` here so changes made by later
                    # callbacks will not be affected.
                    if tracee.singlesteps > 0:
                        tracee.singlesteps -= 1

                    # Reading `at_syscall` probably reads the tracee's registers
                    # and/or memory, so we read it here and then flush the

                    # If we're entering or exiting a syscall we must continue
                    # the tracee with `PTRACE_SYSCALL` in order to observe that.
                    if at_syscall or tracee.in_syscall:
                        ptrace_syscall(pid, cont_signal)
                    else:
                        ptrace_singlestep(pid, cont_signal)

                else:
                    tracee._was_singlestepped = False
                    ptrace_syscall(pid, cont_signal)

            except OSError as e:
                raise
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
                _debug('Traceback:\n' + traceback.format_exc())

        for tracer in self.tracers:
            # Since tracers may be added (or removed) at any time we make sure
            # that their `engine` property is set correctly before triggering
            # any callback
            tracer.engine = self
            run(getattr(tracer, 'on_' + event, None))

        for func, flags in self._callbacks[event].items():
            if flags.get('once'):
                del callbacks[func]
            run(func)

        return out

    def _run_syscall_callbacks(self, tracee):
        # Collect return value override(s).
        syscall = tracee.syscall

        rets = []
        if tracee.in_syscall:
            rets += self._run_callbacks('syscall',
                                        tracee, syscall, syscall.args)
            rets += self._run_callbacks(syscall.name, tracee, syscall.args)
        else:
            rets += self._run_callbacks('syscall_return',
                                        tracee, syscall, syscall.retval)
            rets += self._run_callbacks(syscall.name + '_return',
                                        tracee, syscall.retval)

        rets_ = []
        for f, r in rets:
            bits = tracee.wordsize * 8
            lb = -2**(bits - 1)
            ub = 2**bits - 1
            if not isinstance(r, (int, long)) or r < lb or r > ub:
                _log.warn(
                    'callbacks must return an integer [-2^%d;2^%d), ' \
                    '%s returned %r' % (bits - 1, bits, _funcdesc(f), r)
                )
                continue
            r &= ub
            rets_.append((f, r))
        rets = rets_

        if rets:
            func, retval = rets[-1]
            if len(rets) > 1:
                _log.warn('multiple syscall return values; last ' \
                          'callback takes precedence: %r' % \
                          _funcdesc(func))
            return retval

    def _run_signal_callbacks(self, tracee):
        # Collect signal override(s).
        siginfo = tracee.siginfo
        sigs = self._run_callbacks('signal', tracee, siginfo)
        sigs += self._run_callbacks(siginfo.signame, tracee, siginfo)
        # Also call functions named e.g. `on_TRAP`
        sigs += self._run_callbacks(siginfo.signame[3:], tracee, siginfo)
        if sigs:
            func, signo = sigs[-1]
            if len(sigs) > 1:
                _log.warn('multiple signal numbers; last ' \
                          'callback takes precedence: %r' % \
                          _funcdesc(func))
            return signo

    def _new_tracee(self, pid, parent=None, clone_flags=0):
        _debug('new tracee, <PID:%d>' % pid)
        tracee = Tracee(pid, parent, clone_flags)
        assert pid not in self.tracees, \
            '<PID:%d> is already a tracee' % pid
        self.tracees[pid] = tracee
        self._run_callbacks('birth', tracee)
        ptrace_syscall(pid, 0)

    def _del_tracee(self, tracee):
        assert tracee in tracee.thread_group, \
            'tracee <PID:%d> is not i its own thread group' % tracee.pid
        tracee.thread_group.remove(tracee)
        del self.tracees[tracee.pid]

    def _detect_personality(self, tracee):
        cur_pers = personality(tracee)
        if cur_pers != tracee.personality:
            old_pers = tracee.personality
            _debug('personality change %d (%d -> %d)' % \
                   (tracee.pid, old_pers, cur_pers))
            tracee.personality = cur_pers
            self._run_callbacks('personality_change', tracee, old_pers)
