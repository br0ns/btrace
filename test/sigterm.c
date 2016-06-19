#include <signal.h>

int main(int argc, char *argv[]) {
  return raise(SIGTERM);
}
