#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/sched.h>
#include <sys/wait.h>

#include "util.c"

void thread(void) {
  char *args[] = {
    "/bin/echo",
    "Hello, world!",
    NULL
  };
  sleep(1);
  execv(args[0], args);
}

uint8_t stack[1<<16];

int main(int argc, char *argv[]) {
  if (0 > start_thread(thread,
                       (void*)(stack + sizeof(stack) - sizeof(long)))) {
    printf("start_thread() failed");
    return EXIT_FAILURE;
  }

  syscall(SYS_exit, EXIT_SUCCESS);
}
