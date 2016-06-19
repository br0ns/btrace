#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

int main(int argc, char *argv[]) {
  (void)mmap((void*)0x410000, 0x420000, 7, 0x32, -1, 0x430000);
}
