#include <inc/types.h>
#include <inc/time.h>
#include <inc/stdio.h>
#include <inc/lib.h>

void
umain(int argc, char **argv) {
    unsigned number = sys_rdrand();
    cprintf("NUMBER: %u\n", number);
}
