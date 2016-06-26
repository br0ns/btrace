#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  int i;

  for (i = 0; i < 99; i++) {
    if (fork() == 0) {
      printf("Child #%d reporting for duty\n", i);
      _exit(0);
    }
  }

  return EXIT_SUCCESS;
}
