#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#if !(defined(__i386__) || defined(__amd64__))
#error "architecture not supported"
#endif

static const char *hello = "Hello, world!\n";

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  long retval;

  /* Make sure the string lives in 32 bit memory space */
  void *buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                   -1, 0);
  if (MAP_FAILED == buf) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  strcpy(buf, hello);

  __asm__("int $0x80"
          : "=a" (retval)
          : "0" (4), /* SYS_write in 32 bit mode */
            "b" (STDOUT_FILENO),
            "c" (buf),
            "d" (strlen(hello))
          );

  printf("ret = %ld\n", retval);

  return EXIT_SUCCESS;
}
