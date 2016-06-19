#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  char *args[] = {
    "xxx",
    "Hello, world!",
    NULL
  };
  execv(args[0], args);
  return EXIT_FAILURE;
}
