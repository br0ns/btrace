#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>

void handler(int signum, siginfo_t *si, void *ctx) {
  (void)ctx;

  printf("signum = %d, si_signo = %d\n", signum, si->si_signo);
}

int main(int argc, char *argv[]) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));

  sa.sa_sigaction = handler;

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;

  if (0 != sigaction(SIGUSR1, &sa, NULL)) {
    perror("sigaction() failed");
    exit(-1);
  }

  if (0 != sigaction(SIGUSR2, &sa, NULL)) {
    perror("sigaction() failed");
    exit(-1);
  }

  raise(SIGUSR1);
  return EXIT_SUCCESS;
}
