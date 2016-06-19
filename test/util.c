#include <stdlib.h>
#include <linux/sched.h>
#include <syscall.h>
#include <signal.h>

/* Code after example by Linus:
 *   http://www.tldp.org/FAQ/Threads-FAQ/clone.c
 */
pid_t start_thread(void (*fn)(void), void *newstack) {
  long res, flags;

  flags \
    = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | SIGCHLD;

#ifdef __i386__
  /* Argument constraints:
   *   = : Argument is written to
   *   a : EAX
   *   0 : Input is in same position as output %0
   *   i : Intermediate integer value
   *   r : Any general purpose register
   *   b : EBX
   *   c : ECX
   * Argument numbering:
   *   Input arguments : %0 ... %(n - 1)
   *   Output arguments: %n ... %m
   * Jump targets:
   *   Labels are numbers, jump targets are label numbers followed by 'f' for
   *   forward or 'b' for backwards.
   * References:
   *   https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html#InputOperands
   *   https://gcc.gnu.org/onlinedocs/gcc/Simple-Constraints.html#Simple-Constraints
   *   https://gcc.gnu.org/onlinedocs/gcc/Modifiers.html#Modifiers
   *   https://gcc.gnu.org/onlinedocs/gcc/Machine-Constraints.html#Machine-Constraints
   */
  asm volatile
    ("int $0x80         \n"  /* SYS_clone is in EAX already */
     "testl %0,%0       \n"  /* Check return value          */
     "jne 1f            \n"  /* Jump if parent              */
     "call *%3          \n"  /* Call thread                 */
     "movl %2,%0        \n"
     "int $0x80         \n"  /* Exit thread                 */
     "1:\t"
     :"=a" (res)
     :"0" (SYS_clone), "i" (SYS_exit),
      "r" (fn),
      "b" (flags),
      "c" (newstack));
#endif

#ifdef __amd64__
  asm volatile
    ("syscall           \n"  /* SYS_clone is in RAX already */
     "test %0,%0        \n"  /* Check return value          */
     "jne 1f            \n"  /* Jump if parent              */
     "call *%3          \n"  /* Call thread                 */
     "mov %2,%0         \n"
     "syscall           \n"  /* Exit thread                 */
     "1:\t"
     :"=a" (res)
     :"0" (SYS_clone), "i" (SYS_exit),
      "r" (fn),
      "D" (flags),
      "S" (newstack));
#endif

  return res;
}
