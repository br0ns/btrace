class ThreadGroup(object):
    def __init__(self, leader):
        self.leader = leader
        self.threads = set([leader])
