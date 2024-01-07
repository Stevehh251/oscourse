#include <inc/lib.h>
#include <inc/x86.h>

#define BUFSIZE 10

void
umain(int argc, char **argv)
{
    char buf[BUFSIZE];
    char *c = buf;
    cprintf("Input:\n");
    while ((*c++ = getchar()) != '\r' && *(c - 1) != '\n') cputchar(*(c - 1));
    cputchar('\n');
    cprintf("Seems okay, no fail\n");
} 
