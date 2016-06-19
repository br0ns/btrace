#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  exit(42);
  /* Does not return */
  return EXIT_FAILURE;
}
