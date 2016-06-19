#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/sched.h>
#include <sys/wait.h>

#include "util.c"

void thread1(void) {
  for (;;);

}

void thread2(void) {
  char *args[] = {
    "/bin/echo",
    "Hello, world!",
    NULL
  };
  sleep(1);
  execv(args[0], args);
}

uint8_t stack1[1<<16];
uint8_t stack2[1<<16];

int main(int argc, char *argv[]) {
  void *newstack;

  if (0 > start_thread(thread1,
                       (void*)(stack1 + sizeof(stack1) - sizeof(long)))) {
    printf("start_thread() failed");
    return EXIT_FAILURE;
  }

  if (0 > start_thread(thread2,
                       (void*)(stack2 + sizeof(stack2) - sizeof(long)))) {
    printf("start_thread() failed");
    return EXIT_FAILURE;
  }
  sleep(999);

  /* for(;;); */
}
