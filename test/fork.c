#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

int main(int argc, char *argv[]) {
  switch (fork()) {
  case 0:
    puts("I'm the child!");
    break;
  case -1:
    perror("fork");
    return EXIT_FAILURE;
  default:
    if (-1 == puts("I'm the parent!")) {
      perror("puts");
    }
    break;
  }
  return EXIT_SUCCESS;
}
