char hello[] = "hello\n";

int main(int argc, char *argv[]) {
  __asm__(
          "mov $1, %%rbx\n"
          "mov %0, %%rcx\n"
          "mov $6, %%rdx\n"
          "mov $4, %%rax\n"
          "int $0x80\n"
          :
          : "i" (hello)
          );
}
