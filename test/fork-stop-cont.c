#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

int main(int argc, char *argv[]) {
  pid_t pid;
  int i;
  switch ((pid = fork())) {
  case 0:
    for (i = 0; i < 10; i++) {
      printf("%d I'm the child!\n", i);
      usleep(200000);
    }
    break;
  case -1:
    perror("fork");
    return EXIT_FAILURE;
  default:
    puts("I'm the parent!");
    sleep(1);
    kill(pid, SIGSTOP);
    sleep(1);
    kill(pid, SIGCONT);
    break;
  }
  return EXIT_SUCCESS;
}
