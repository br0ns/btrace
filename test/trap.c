#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

int main(int argc, char *argv[]) {
  asm("int3");
  /* Does not return */
  return EXIT_FAILURE;
}
