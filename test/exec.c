#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  char *args[] = {
    "/bin/echo",
    "Hello, world!",
    NULL
  };
  execv(args[0], args);
  /* Does not return */
  return EXIT_SUCCESS;
}
