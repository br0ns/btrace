CC=gcc

TARGETS=                 \
  99forks                \
  clone-child-exec       \
  clone-untraced         \
  exec                   \
  exec-failed            \
  exit42                 \
  fork                   \
  fork-stop-cont         \
  hello                  \
  infloop-busy           \
  infloop-sleep          \
  kill                   \
  mmap                   \
  siginfo                \
  sigkill                \
  sigsegv                \
  sigterm                \
  sigwinch               \
  term                   \
  trap                   \

TARGETS:=$(patsubst %, %.i386, $(TARGETS)) \
         $(patsubst %, %.amd64, $(TARGETS))

all: $(TARGETS)

%.amd64: %.c
	$(CC) $(CFLAGS) -o $@ $<

%.i386: %.c
	$(CC) -m32 $(CFLAGS) -o $@ $<


%.strace: %
	strace -f -o $@ ./$< || true

.PHONY: clean

clean: SHELL:=/bin/bash -O extglob
clean:
	rm -f !(*.c|Makefile)
