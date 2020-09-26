class TracerDoc(object):
    '''This "tracer" implements nothing; it's sole purpose is to document the
    tracer API.
    '''

    def on_birth(self, tracee):
        pass

    def on_death(self, tracee, status):
        pass

    def on_kill(self, tracee):
        pass

    def on_stop(self, tracee):
        pass

    def on_syscall(self, tracee, syscall, args):
        '''This function is called when a tracee performs a syscall'''
        pass

    def on_syscall_return(self, tracee, syscall, retval):
        pass

    def on_read(self, tracee, args):
        pass

    def on_read_return(self, tracee, retval):
        pass

    def on_repid(self, tracee, oldpid):
        pass

    def on_cont(self, tracee):
        pass

    def on_personality_change(self, tracee, oldpers):
        pass

    def on_step(self, tracee, siginfo):
        pass

    def on_signal(self, tracee, siginfo):
        pass
