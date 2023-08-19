#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <clock.h>
#include <syscall.h>
#include <current.h>
#include <lib.h>
#include <copyinout.h>
#include <vnode.h>
#include <vfs.h>
#include <limits.h>
#include <uio.h>
#include <proc.h>

int
sys_getcwd(char *buf, size_t size, char *retval) {
    #if OPT_SYSCALLS
    //TODO
    char *x = buf
    size_t y = size;
    #endif
    
    return NULL;
}

int
sys_chdir(const char *path) {
    #if OPT_SYSCALLS
    char *x = path;
    //TODO
    #endif

    return 0;
}
