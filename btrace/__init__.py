from .engine import Engine

# Install a "null" log handler to suppress the "no handlers..." warning that
# would otherwise be printed.  Details:
#   https://docs.python.org/3.1/library/logging.html#configuring-logging-for-a-library
def closure():
    import logging
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass
    handler = NullHandler()
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
closure()

# Clean up namespace
del closure
