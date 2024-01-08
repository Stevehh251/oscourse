#include <inc/lib.h>
#include <inc/elf.h>

#define UTEMP2USTACK(addr, off) ((void *)(addr) + (USER_STACK_TOP - USER_STACK_SIZE) - UTEMP - off)

/* Helper functions for spawn. */
static int init_stack(envid_t child, const char **argv, struct Trapframe *tf);
static int map_segment(envid_t child, struct Elf *elf, uintptr_t va, long load_offset, size_t memsz,
            int fd, size_t filesz, off_t fileoffset, int perm);
static int copy_shared_region(void *start, void *end, void *arg);
static unsigned long random_region_base(uintptr_t start, uintptr_t end, size_t len);
static int fix_reloc(envid_t child, struct Elf *elf, long load_offset, uintptr_t va, size_t filesz, int fd, void *store);

/* Spawn a child process from a program image loaded from the file system.
 * prog: the pathname of the program to run.
 * argv: pointer to null-terminated array of pointers to strings,
 *   which will be passed to the child as its command-line arguments.
 * Returns child envid on success, < 0 on failure. */
int
spawn(const char *prog, const char **argv) {
    unsigned char elf_buf[512];
    int res;

    /* This code follows this procedure:
     *
     *   - Open the program file.
     *
     *   - Read the ELF header, as you have before, and sanity check its
     *     magic number.  (Check out your load_icode!)
     *
     *   - Use sys_exofork() to create a new environment.
     *
     *   - Set child_tf to an initial struct Trapframe for the child.
     *
     *   - Call the init_stack() function above to set up
     *     the initial stack page for the child environment.
     *
     *   - Map all of the program's segments that are of p_type
     *     ELF_PROG_LOAD into the new environment's address space.
     *     Use the p_flags field in the Proghdr for each segment
     *     to determine how to map the segment:
     *
     *    * If the ELF flags do not include ELF_PROG_FLAG_WRITE,
     *      then the segment contains text and read-only data.
     *      Use read_map() to read the contents of this segment,
     *      and map the pages it returns directly into the child
     *        so that multiple instances of the same program
     *      will share the same copy of the program text.
     *        Be sure to map the program text read-only in the child.
     *        Read_map is like read but returns a pointer to the data in
     *        *blk rather than copying the data into another buffer.
     *
     *    * If the ELF segment flags DO include ELF_PROG_FLAG_WRITE,
     *      then the segment contains read/write data and bss.
     *      As with load_icode() in Lab 3, such an ELF segment
     *      occupies p_memsz bytes in memory, but only the FIRST
     *      p_filesz bytes of the segment are actually loaded
     *      from the executable file - you must clear the rest to zero.
     *        For each page to be mapped for a read/write segment,
     *        allocate a page in the parent temporarily at UTEMP,
     *        read() the appropriate portion of the file into that page
     *      and/or use memset() to zero non-loaded portions.
     *      (You can avoid calling memset(), if you like, if
     *      page_alloc() returns zeroed pages already.)
     *        Then insert the page mapping into the child.
     *        Look at init_stack() for inspiration.
     *        Be sure you understand why you can't use read_map() here.
     *
     *     Note: None of the segment addresses or lengths above
     *     are guaranteed to be page-aligned, so you must deal with
     *     these non-page-aligned values appropriately.
     *     The ELF linker does, however, guarantee that no two segments
     *     will overlap on the same page; and it guarantees that
     *     PGOFF(ph->p_offset) == PGOFF(ph->p_va).
     *
     *   - Call sys_env_set_trapframe(child, &child_tf) to set up the
     *     correct initial eip and esp values in the child.
     *
     *   - Start the child process running with sys_env_set_status(). */

    // TODO Properly load ELF and check errors

    int fd = open(prog, O_RDONLY);
    if (fd < 0) return fd;

    /* Read elf header */
    struct Elf *elf = (struct Elf *)elf_buf;
    res = readn(fd, elf_buf, sizeof(elf_buf));
    if (res != sizeof(elf_buf)) {
        cprintf("Wrong ELF header size or read error: %i\n", res);
        close(fd);
        return -E_NOT_EXEC;
    }
    if (elf->e_magic != ELF_MAGIC ||
        elf->e_elf[0] != 2 /* 64-bit */ ||
        elf->e_elf[1] != 1 /* little endian */ ||
        elf->e_elf[2] != 1 /* version 1 */ ||
        (elf->e_type != ET_EXEC && elf->e_type != ET_DYN) || /* executable or PIE */ 
        elf->e_machine != 0x3E /* amd64 */) {
        cprintf("Elf magic %08x want %08x\n", elf->e_magic, ELF_MAGIC);
        close(fd);
        return -E_NOT_EXEC;
    }

    /* Create new child environment */
    if ((int)(res = sys_exofork()) < 0) goto error2;
    envid_t child = res;

    trace("\nSpawning new exec in env [%d]...\n", child);

    trace("[%d] Type of ELF %s\n", child, elf->e_type == ET_EXEC ? "no-pie" : "pie");

    struct Proghdr *ph;

    long load_offset = 0;
#if ENABLE_ASLR
    /* Use ASLR on entry point if PIE */
    if (elf->e_type == ET_DYN) {
        /* Calculate address range of program segments */
        uintptr_t low_addr = UTEXT_MAX;
        uintptr_t high_addr = UTEXT;
        ph = (struct Proghdr *)(elf_buf + elf->e_phoff);
        for (size_t i = 0; i < elf->e_phnum; i++, ph++) {
            if (ph->p_type != ELF_PROG_LOAD) continue;
            low_addr = MIN(low_addr, ph->p_va);
            high_addr = MAX(high_addr, ph->p_va + ph->p_memsz);
        }
        low_addr = ROUNDDOWN(low_addr, PAGE_SIZE);
        high_addr = ROUNDUP(high_addr, PAGE_SIZE);

        /* Get random offset to load image at */
        uintptr_t load_base = random_region_base(UTEXT, UTEXT_MAX, high_addr - low_addr);
        load_offset = load_base - elf->e_entry;
        trace("[%d] Image ASLR load base %lx\n", child, load_base);
    }
#endif

    /* Set up program segments as defined in ELF header. */
    ph = (struct Proghdr *)(elf_buf + elf->e_phoff);
    for (size_t i = 0; i < elf->e_phnum; i++, ph++) {
        if (ph->p_type != ELF_PROG_LOAD) continue;
        int perm = 0;

        if (ph->p_flags & ELF_PROG_FLAG_WRITE) perm |= PROT_W;
        if (ph->p_flags & ELF_PROG_FLAG_READ) perm |= PROT_R;
        if (ph->p_flags & ELF_PROG_FLAG_EXEC) perm |= PROT_X;

        trace("[%d] Mapping segment sized [%lx, %lx] into [%lx, %lx] with perm %d\n", 
            child, ph->p_va + load_offset, ph->p_va + load_offset + ph->p_memsz, 
            ROUNDDOWN(ph->p_va + load_offset, PAGE_SIZE), ROUNDUP(ph->p_va + load_offset + ph->p_memsz, PAGE_SIZE), perm);

        if ((res = map_segment(child, elf, ph->p_va, load_offset, ph->p_memsz,
                               fd, ph->p_filesz, ph->p_offset, perm)) < 0)
            goto error;
    }

    /* Set up trap frame, including initial stack. */
    struct Trapframe child_tf = envs[ENVX(child)].env_tf;
    child_tf.tf_rip = elf->e_entry + load_offset;

    trace("[%d] Entry at %lx\n", child, child_tf.tf_rip);

    if ((res = init_stack(child, argv, &child_tf)) < 0) goto error;

#ifdef SAN_ENABLE_UASAN
    res = sys_alloc_region(child, (void *) SANITIZE_USER_SHADOW_BASE, SANITIZE_USER_SHADOW_SIZE, PTE_U | PTE_W | PTE_P);
    if (res)
        return res;
#endif

    close(fd);

    /* Copy shared library state. */
    if ((res = foreach_shared_region(copy_shared_region, &child)) < 0)
        panic("copy_shared_region: %i", res);

    if ((res = sys_env_set_trapframe(child, &child_tf)) < 0)
        panic("sys_env_set_trapframe: %i", res);

    if ((res = sys_env_set_status(child, ENV_RUNNABLE)) < 0)
        panic("sys_env_set_status: %i", res);

    return child;

error:
    trace("[%d] Something went wrong with code %d\n", child, res);
    sys_env_destroy(child);
error2:
    close(fd);

    return res;
}

/* Spawn, taking command-line arguments array directly on the stack.
 * NOTE: Must have a sentinal of NULL at the end of the args
 * (none of the args may be NULL). */
int
spawnl(const char *prog, const char *arg0, ...) {
    /* We calculate argc by advancing the args until we hit NULL.
     * The contract of the function guarantees that the last
     * argument will always be NULL, and that none of the other
     * arguments will be NULL. */
    int argc = 0;
    va_list vl;
    va_start(vl, arg0);
    while (va_arg(vl, void *) != NULL) argc++;
    va_end(vl);

    /* Now that we have the size of the args, do a second pass
     * and store the values in a VLA, which has the format of argv */
    const char *argv[argc + 2];
    argv[0] = arg0;
    argv[argc + 1] = NULL;

    va_start(vl, arg0);
    unsigned i;
    for (i = 0; i < argc; i++) {
        argv[i + 1] = va_arg(vl, const char *);
    }
    va_end(vl);

    return spawn(prog, argv);
}

/* Set up the initial stack page for the new child process with envid 'child'
 * using the arguments array pointed to by 'argv',
 * which is a null-terminated array of pointers to null-terminated strings.
 *
 * On success, returns 0 and sets *init_esp
 * to the initial stack pointer with which the child should start.
 * Returns < 0 on failure. */
static int
init_stack(envid_t child, const char **argv, struct Trapframe *tf) {
    size_t string_size;
    int argc, i, res;
    char *string_store;
    uintptr_t *argv_store;

    /* Count the number of arguments (argc)
     * and the total amount of space needed for strings (string_size). */
    string_size = 0;
    for (argc = 0; argv[argc] != 0; argc++)
        string_size += strlen(argv[argc]) + 1;

    /* Determine where to place the strings and the argv array.
     * Set up pointers into the temporary page 'UTEMP'; we'll map a page
     * there later, then remap that page into the child environment
     * at (USER_STACK_TOP - USER_STACK_SIZE).
     * strings is the topmost thing on the stack. */
    string_store = (char *)UTEMP + USER_STACK_SIZE - string_size;
    /* argv is below that.  There's one argument pointer per argument, plus
     * a null pointer. */
    argv_store = (uintptr_t *)(ROUNDDOWN(string_store, sizeof(uintptr_t)) - sizeof(uintptr_t) * (argc + 1));

    /* Make sure that argv, strings, and the 2 words that hold 'argc'
     * and 'argv' themselves will all fit in a single stack page. */
    if ((void *)(argv_store - 2) < (void *)UTEMP) return -E_NO_MEM;

    /* Allocate the stack pages at UTEMP. */
    if ((res = sys_alloc_region(0, UTEMP, USER_STACK_SIZE, PROT_RW)) < 0) return res;

    /*    * Initialize 'argv_store[i]' to point to argument string i,
     *      for all 0 <= i < argc.
     *      Also, copy the argument strings from 'argv' into the
     *      newly-allocated stack page.
     *
     *    * Set 'argv_store[argc]' to 0 to null-terminate the args array.
     *
     *    * Push two more words onto the child's stack below 'args',
     *      containing the argc and argv parameters to be passed
     *      to the child's umain() function.
     *      argv should be below argc on the stack.
     *      (Again, argv should use an address valid in the child's
     *      environment.)
     *
     *    * Set *init_esp to the initial stack pointer for the child,
     *      (Again, use an address valid in the child's environment.) */

    uintptr_t stack_base = USER_STACK_TOP - USER_STACK_SIZE;
    uintptr_t stack_top = USER_STACK_TOP;
    long stack_offset = 0;
#ifdef ENABLE_ASLR
    stack_base = random_region_base(USER_STACK_BOTTOM, USER_STACK_TOP, USER_STACK_SIZE);
    stack_top = stack_base + USER_STACK_SIZE;
    stack_offset = (long) USER_STACK_TOP - stack_top;
    trace("[%d] Stack ASLR offset  %lx\n", child, stack_offset);
#endif

    for (i = 0; i < argc; i++) {
        argv_store[i] = UTEMP2USTACK(string_store, stack_offset);
        strcpy(string_store, argv[i]);
        string_store += strlen(argv[i]) + 1;
    }
    argv_store[argc] = 0;
    assert(string_store == (char *)UTEMP + USER_STACK_SIZE);

    argv_store[-1] = UTEMP2USTACK(argv_store, stack_offset);
    argv_store[-2] = argc;

    tf->tf_rsp = UTEMP2USTACK(&argv_store[-2], stack_offset);

    /* After completing the stack, map it into the child's address space
     * and unmap it from ours! */
    if (sys_map_region(0, UTEMP, child, (void *)stack_base, USER_STACK_SIZE, PROT_RW) < 0) goto error;

    trace("[%d] Stack successfully initiated at [%lx, %lx]\n", child, stack_base, stack_top);
    trace("[%d] Stack pointer placed at %lx\n", child, tf->tf_rsp);

error:
    if (sys_unmap_region(0, UTEMP, USER_STACK_SIZE) < 0) goto error;
    return res;
}

static int
copy_shared_region(void *start, void *end, void *arg) {
    envid_t child = *(envid_t *)arg;
    trace("[%d] Shared region at [%lx, %lx]\n", child, (uintptr_t)start, (uintptr_t)end);
    return sys_map_region(0, start, child, start, end - start, get_prot(start));
}


static int
map_segment(envid_t child, struct Elf *elf, uintptr_t va, long load_offset, size_t memsz,
            int fd, size_t filesz, off_t fileoffset, int perm) {

    va += load_offset;
    /* Fixup unaligned destination */
    int res = PAGE_OFFSET(va);
    if (res) {
        va -= res;
        memsz += res;
        filesz += res;
        fileoffset -= res;
    }

    // LAB 11_Done: Your code here
    /* NOTE: There's restriction on maximal filesz
     * for each program segment (HUGE_PAGE_SIZE) */
    if (filesz > HUGE_PAGE_SIZE || filesz > memsz)
        return -E_INVALID_EXE;

    /* Allocate filesz - memsz in child */
    if (memsz > filesz) {
        res = sys_alloc_region(child, (void *)va + ROUNDUP(filesz, PAGE_SIZE), ROUNDUP(memsz - filesz, PAGE_SIZE), perm);
        if (res)
            return res;
    }

    /* Allocate filesz in parent to UTEMP */
    if (filesz == 0)
        return 0;
    res = sys_alloc_region(CURENVID, UTEMP, ROUNDUP(filesz, PAGE_SIZE), PTE_U | PTE_W | PTE_P);
    if (res)
        return res;

    /* seek() fd to fileoffset  */
    res = seek(fd, fileoffset);
    if (res)
        return res;

    /* read filesz to UTEMP */
    res = readn(fd, UTEMP, filesz);
    if (res < 0)
        return res;

    /* Fix dynamic relocations if PIE */
    if (elf->e_type == ET_DYN) {
        res = fix_reloc(child, elf, load_offset, va, filesz, fd, UTEMP + ROUNDUP(filesz, PAGE_SIZE));
        if (res)
            return res;
    }

    /* Map read section conents to child */
    res = sys_map_region(CURENVID, UTEMP, child, (void *)va, ROUNDUP(filesz, PAGE_SIZE), perm);
    if (res)
        return res;

    /* Unmap it from parent */
    res = sys_unmap_region(CURENVID, UTEMP, ROUNDUP(filesz, PAGE_SIZE));
    if (res)
        return res;

    return 0;
}


static unsigned long
random_region_base(uintptr_t start, uintptr_t end, size_t len) {
    size_t range = end - len - start;
    if (end <= start + len)
        return 0;
    return ROUNDDOWN((unsigned long)sys_rdrand() % range + start, PAGE_SIZE);
}

static int
fix_reloc(envid_t child, struct Elf *elf, long load_offset, uintptr_t va, size_t filesz, int fd, void *store) {
    int res = 0;
    if (trace_reloc) trace("[%d] Going through section headers, counting %u\n", child, elf->e_shnum); 

    /* Alloc memory for section headers */
    size_t secthdr_size = elf->e_shnum * sizeof(struct Secthdr);
    res = sys_alloc_region(CURENVID, store, ROUNDUP(secthdr_size, PAGE_SIZE), PTE_U | PTE_W | PTE_P);

    /* seek secthdr and read it */
    res = seek(fd, elf->e_shoff);
    res = readn(fd, store, secthdr_size);

    /* Go through relocation sections */
    struct Secthdr *sh = (struct Secthdr *) store;
    void *rela = ROUNDUP((void *) store + secthdr_size, PAGE_SIZE);
    for (size_t i = 0; i < elf->e_shnum; i++, sh++) {
        if (sh->sh_type == ELF_SHT_RELA || sh->sh_type == ELF_SHT_REL) {
            if (trace_reloc) trace("[%d] Rela section found at pos %lu\n", child, i);

            /* Alloc memory for reloc sector */
            res = sys_alloc_region(CURENVID, rela, ROUNDUP(sh->sh_size, PAGE_SIZE), PTE_U | PTE_W | PTE_P);

            /* Seek and read*/
            res = seek(fd, sh->sh_offset);
            res = readn(fd, rela, sh->sh_size);

            // /* Get lower and higher offsets to be relocated */
            // uintptr_t lower_off = -1, higher_off = 0; 
            // if (sh->sh_type == ELF_SHT_RELA) {
            //     size_t reloc_cnt = sh->sh_size / sizeof(struct Elf64_Rela);
            //     struct Elf64_Rela *entry = (struct Elf64_Rela *) rela;
            //     for (size_t i = 0; i < reloc_cnt; i++, entry++) {
            //         lower_off = MIN(lower_off, entry->r_offset);
            //         higher_off = MAX(higher_off, entry->r_offset);
            //     }
            // }
            // if (sh->sh_type == ELF_SHT_REL) {
            //     /*TODO*/
            // }
            // lower_off = ROUNDDOWN(lower_off, PAGE_SIZE);
            // higher_off = ROUNDUP(higher_off, PAGE_SIZE);
            // cprintf("[%d] Calculated lower and higher offsets %lx, %lx\n", child, lower_off, higher_off);

            /* Apply relocations */
            if (sh->sh_type == ELF_SHT_RELA) {
                size_t reloc_cnt = sh->sh_size / sizeof(struct Elf64_Rela);
                if (trace_reloc) trace("[%d] Relocations cnt %lu\n", child, reloc_cnt);
                struct Elf64_Rela *entry = (struct Elf64_Rela *) rela;
                for (size_t i = 0; i < reloc_cnt; i++, entry++) {
                    if (entry->r_offset + load_offset < va || entry->r_offset + load_offset >= va + filesz) {
                        continue;
                    }
                    int64_t *reloc_addr = (int64_t *) (entry->r_offset + load_offset - va + UTEMP);
                    if (trace_reloc) trace("[%d] Reloc address %lx, its content %lx, addent value %lx\n", child, entry->r_offset, *reloc_addr, entry->r_addend);
                    *reloc_addr = entry->r_addend + load_offset;
                }
            }
            if (sh->sh_type == ELF_SHT_REL) {
                /*TODO*/
            }

            /* Unmap reloc sector*/
            res = sys_unmap_region(CURENVID, rela, ROUNDUP(sh->sh_size, PAGE_SIZE));
        }
    
    }
    /* Unmap memory */
    res = sys_unmap_region(CURENVID, store, ROUNDUP(secthdr_size, PAGE_SIZE));
    
    return res;
}