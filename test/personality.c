#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

char hello[] = "hello\n";

int main(int argc, char *argv[]) {
  char *txt;
  txt = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT,
             -1, 0);
  strcpy(txt, hello);
#ifdef __amd64__
  __asm__(
          "mov $1, %%rbx\n"
          "mov %0, %%rcx\n"
          "mov $6, %%rdx\n"
          "mov $4, %%rax\n"
          "int $0x80\n"
          :
          : "p" (txt)
          );
#else
  __asm__(
          "mov $1, %%ebx\n"
          "mov %0, %%ecx\n"
          "mov $6, %%edx\n"
          "mov $4, %%eax\n"
          "int $0x80\n"
          :
          : "p" (txt)
          );
#endif
}
