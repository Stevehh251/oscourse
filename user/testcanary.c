#include <inc/lib.h>
#include <inc/x86.h>

#define BUFSIZE 10

extern unsigned __stack_chk_guard;

void
umain(int argc, char **argv)
{
    cprintf("%u\n", __stack_chk_guard);
    char buf[BUFSIZE];
    char *c = buf;
    cprintf("Input:\n");
    while ((*c++ = getchar()) != '\r' && *(c - 1) != '\n') cputchar(*(c - 1));
    cputchar('\n');
    cprintf("Seems okay, no fail\n");
    cprintf("%u\n", __stack_chk_guard);
} 
