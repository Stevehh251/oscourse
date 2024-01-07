/* Called from entry.S to get us going.
 * entry.S already took care of defining envs, pages, uvpd, and uvpt */

#include <inc/lib.h>
#include <inc/x86.h>

extern void umain(int argc, char **argv);

const volatile struct Env *thisenv;
const char *binaryname = "<unknown>";

#ifdef JOS_PROG
void (*volatile sys_exit)(void);
#endif

extern unsigned __stack_chk_guard;

__attribute__((no_stack_protector, noreturn))
void __stack_chk_fail(void)
{
    // panic("Canary check failed: expected %x", *(uint32_t*)UCANARY_VAL);
    panic("Canary check failed: expected %x", __stack_chk_guard);
}

void __attribute__ ((no_stack_protector, noreturn))
__stack_chk_fail_local (void)
{
    __stack_chk_fail();
}

void
libmain(int argc, char **argv) {
    /* Perform global constructor initialisation (e.g. asan)
     * This must be done as early as possible */
    extern void (*__ctors_start)(), (*__ctors_end)();
    void (**ctor)() = &__ctors_start;
    while (ctor < &__ctors_end) (*ctor++)();

    /* Set thisenv to point at our Env structure in envs[]. */

    // LAB 8_Done: Your code here
    thisenv = &envs[ENVX(sys_getenvid())];

    /* Save the name of the program so that panic() can use it */
    if (argc > 0) binaryname = argv[0];

    /* Call user main routine */
    umain(argc, argv);

#ifdef JOS_PROG
    sys_exit();
#else
    exit();
#endif
}
