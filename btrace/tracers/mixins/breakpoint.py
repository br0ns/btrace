class Breakpoint(object):
  breakpoints = set()
  _orig = dict()

  def breakpoint(self, addr):
    self.breakpoints.add(addr)
    self._orig
