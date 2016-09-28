#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
    puts("NOPE!");
    return EXIT_FAILURE;
  }
  puts("Hello, world");

  return EXIT_SUCCESS;
}
