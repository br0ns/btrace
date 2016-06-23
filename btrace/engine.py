import os
import errno
import logging
import traceback
import types

from collections import defaultdict

from .ptrace      import *
from .signals     import *
from .syscalls    import *
from .info        import *
from .tracee      import Tracee
from .personality import personality

_log = logging.getLogger(__name__)

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
PTRACE_O_FOLLOW = PTRACE_O_TRACECLONE   | \
                  PTRACE_O_TRACEFORK    | \
                  PTRACE_O_TRACEVFORK

# Corresponding "alias" for events.
PTRACE_EVENTS_FOLLOW = (PTRACE_EVENT_CLONE,
                        PTRACE_EVENT_FORK,
                        PTRACE_EVENT_VFORK)

class Engine(object):
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
        self.singlestep = singlestep
        self.tracers = tracers

        self.tracees = {}

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
            _log.debug('enabling follow mode')
            self._ptrace_opts |= PTRACE_O_FOLLOW
        else:
            _log.debug('disabling follow mode')
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

        # We save the flags argument to clone syscalls, because we need it to
        # decide the parent and thread group of newly spawned processes and
        # threads
        clone_flags = {}

        while self.tracees:
            try:
                pid, status = self._wait()
            except OSError as e:
                if e.errno == errno.ECHILD:
                    # This may happen if all the tracees are killed by SIGKILL.
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
                _log.debug('child <PID:%d> is not a tracee' % pid)
                continue

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
                    tracee.personality = personality(tracee)
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

            # This will be sent if we have event-stop
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

            # Logging
            if stopped:
                reason = 'stopped '
                if signal_stop:
                    reason += '(signal <%d:%s>)' % \
                              (siginfo.signo, signal_names[siginfo.signo])
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

            # Tracee exited or was killed by a signal, so remove it.  No need to
            # report this exit as we have already done so when we got
            # PTRACE_EVENT_EXIT
            # Caveat: At the moment (kernel 4.5.0) tracees stop in event-stop
            #   with PTRACE_EVENT_EXIT even if they are killed by SIGKILL.
            #   According to the man page that may change in the future.  We
            #   handle that hypothetical situation below, if ptrace fails with
            #   ESRCH when we continue the tracee
            if exited or signalled:
                self._del_tracee(tracee)
                continue

            # Handle exec's: when a thread which is not the thread group leader
            # executes execve, all other threads in the thread group die and the
            # execve'ing thread becomes leader.  This code must be executed
            # early as `tracee` is in fact the wrong tracee at this point, and
            # we need to correct that.
            if event == PTRACE_EVENT_EXEC:
                oldpid = ptrace_geteventmsg(pid)
                if pid != oldpid:
                    _log.debug('repid (%d -> %d)' % (oldpid, pid))
                    # Neither this tracee nor the thread group leader will
                    # report death, so we must do the clean-up here
                    self._del_tracee(tracee)
                    # This is the correct tracee, it just changed its pid
                    tracee = self.tracees.pop(oldpid)
                    tracee.pid = pid
                    self.tracees[pid] = tracee
                    self._run_callbacks('repid', tracee, oldpid)

            # This tracee was stopped, but now it's running again!
            if not tracee.is_running:
                tracee.is_running = True
                self._run_callbacks('cont', tracee)

            # See if the tracee changed personality
            cur_pers = personality(tracee)
            if cur_pers != tracee.personality:
                old_pers = tracee.personality
                _log.debug('personality change %d (%d -> %d)' % \
                           (pid, old_pers, cur_pers))
                tracee.personality = cur_pers
                self._run_callbacks('personality_change', tracee, old_pers)

            # Handle syscall-enter and syscall-exit
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
                    bits = tracee.wordsize * 8
                    lb = -2**(bits - 1)
                    ub = 2**bits - 1
                    if not isinstance(r, (int, long)) or \
                       r < lb or r > ub:
                        _log.warn(
                            'callbacks must return an integer [-2^%d;2^%d), ' \
                            '%s returned %r' % (bits - 1, bits, _funcdesc(f), r)
                        )
                        continue
                    r &= ub
                    ret_.append((f, r))
                ret = ret_

                if ret:
                    func, retval = ret[-1]
                    if len(ret) > 1:
                        _log.warn('multiple syscall return values; last ' \
                                  'callback takes precedence: %r' % \
                                  _funcdesc(func))

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

                    # The syscall return value was overridden by a tracer
                    else:
                        tracee.syscall.retval = retval
                        _log.debug('overriding retval <%d:%s> -> 0x%x' % \
                                   (syscall.nr, syscall.name, retval))

                # We are about to enter an un-emulated clone syscall and we want
                # to follow the child.  We must save the flags used in the
                # syscall so we can correctly set the parent and thread group of
                # the newly created process/thread when it arrives.  Also, if
                # the `CLONE_UNTRACED` flag is set, we unset it so we become a
                # tracer of the child.  This check needs to be placed here,
                # after the callbacks have run, as the syscall may be changed or
                # simulated by a tracer.  `CLONE_UNTRACED` is defined in
                # /usr/include/linux/sched.h
                CLONE_UNTRACED = 0x00800000
                if self.follow              and \
                   tracee.in_syscall        and \
                   not syscall.emulated     and \
                   syscall.name == 'clone':
                    clone_flags[pid] = syscall.args[0]
                    if syscall.args[0] & CLONE_UNTRACED:
                        syscall.args[0] &= ~CLONE_UNTRACED
                        _log.debug('removed CLONE_UNTRACED in clone syscall')

            # Run callbacks signals and single stepping
            elif signal_stop:
                # If we are single stepping and received a SIGTRAP, we interpret
                # that as a step
                if self.singlestep and siginfo.signo == SIGTRAP:
                    _log.debug('singlestep')
                    self._run_callbacks('step', tracee, siginfo)

                else:
                    # Collect signal number overrides
                    ret = self._run_callbacks('signal', tracee, siginfo)
                    if ret:
                        func, signo = ret[-1]
                        if len(ret) > 1:
                            _log.warn('multiple signal numbers; last ' \
                                      'callback takes precedence: %r' % \
                                      _funcdesc(func))
                        # Override signal
                        cont_signal = signo

            # Ditto for group-stops
            elif group_stop:
                tracee.is_running = False
                self._run_callbacks('stop', tracee)

            # Handle births
            elif event in PTRACE_EVENTS_FOLLOW:
                newpid = ptrace_geteventmsg(pid)
                assert pid in clone_flags, \
                    'got PTRACE_EVENT_{FORK,VFORK,CLONE} but a previous ' \
                    'clone syscall was never observed'
                self._new_tracee(newpid, tracee, clone_flags.pop(pid))

            # Handle deaths
            elif event == PTRACE_EVENT_EXIT:
                status = ptrace_geteventmsg(pid)
                self._run_callbacks('death', tracee, status)

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
                elif self.singlestep:
                    ptrace_singlestep(pid, cont_signal)
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

    def _new_tracee(self, pid, parent=None, clone_flags=0):
        tracee = Tracee(pid, parent, clone_flags)
        assert pid not in self.tracees, \
            '<PID:%d> is already a tracee' % pid
        self.tracees[pid] = tracee
        self._run_callbacks('birth', tracee)

    def _del_tracee(self, tracee):
        assert tracee in tracee.thread_group, \
            'tracee is not i its own thread group'
        tracee.thread_group.remove(tracee)
        del self.tracees[tracee.pid]
