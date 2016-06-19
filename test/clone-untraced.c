#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <linux/sched.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>

int clone(int (*fn)(void *), void *child_stack,
          int flags, void *arg, ...
          /* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ );

pid_t gettid(void) {
  return syscall(SYS_gettid);
}

int thread(void *arg) {
  printf("Thread: PID = %d, TID = %d\n", getpid(), gettid());
  printf("I got: %s\n", arg);
  return 0;
}

uint8_t stack[1<<16];

int main(int argc, char *argv[]) {
  void *newstack;
  pid_t pid;

  newstack = (void*)(stack + sizeof(stack) - sizeof(long));
  printf("Leader: PID = %d, TID = %d\n", getpid(), gettid());
  pid = clone(thread, newstack,
              /* CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_UNTRACED, */
              CLONE_VM | CLONE_SIGHAND | CLONE_THREAD,
              "foobar");
  for (;;) sleep(1);
}
