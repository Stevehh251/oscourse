#include <inc/lib.h>
#include <inc/x86.h>

#define BUFSIZE 10

extern uintptr_t __stack_chk_guard;

void
umain(int argc, char **argv)
{
    cprintf("Canary before: %lx\n", __stack_chk_guard);
    char buf[BUFSIZE];
    char *c = buf;
    cprintf("Input:\n");
    while ((*c++ = getchar()) != '\r' && *(c - 1) != '\n') cputchar(*(c - 1));
    cputchar('\n');

    cprintf("No buffer overflow detected\n");
    cprintf("Canary after: %lx\n", __stack_chk_guard);
} 
