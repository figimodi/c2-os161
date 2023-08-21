/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys__exit.
 * It just avoids crash/panic. Full process exit still TODO
 * Address space is released
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <kern/fcntl.h>
#include <clock.h>
#include <copyinout.h>
#include <syscall.h>
#include <lib.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <mips/trapframe.h>
#include <current.h>
#include <synch.h>
#include <vnode.h>
#include <uio.h>
#include <vfs.h>
#include <fs.h>
#include <list.h>

/*
 * simple proc management system calls
 */
void
sys__exit(int status)
{
#if OPT_SYSCALLS
  struct proc *p = curproc;
  p->p_status = status & 0xff; /* just lower 8 bits returned */
  proc_remthread(curthread);

  V(p->p_sem);
#else
  /* get address space of current process and destroy */
  struct addrspace *as = proc_getas();
  as_destroy(as);
#endif
  thread_exit();

  panic("thread_exit returned (should not happen)\n");
  (void) status; // TODO: status handling
}

int
sys_waitpid(pid_t pid, userptr_t statusp, int options)
{
#if OPT_SYSCALLS
  struct proc *p = proc_search_pid(pid);
  int s;
  (void)options; /* not handled */
  if (p==NULL) return -1;
  s = proc_wait(p);
  if (statusp!=NULL) 
    *(int*)statusp = s;
  return pid;
#else
  (void)options; /* not handled */
  (void)pid;
  (void)statusp;
  return -1;
#endif
}

pid_t
sys_getpid(void)
{
#if OPT_SYSCALLS
  KASSERT(curproc != NULL);
  return curproc->p_pid;
#else
  return -1;
#endif
}

static void
call_enter_forked_process(void *tfv, unsigned long dummy) {
  struct trapframe *tf = (struct trapframe *)tfv;
  (void)dummy;
  enter_forked_process(tf); 
 
  panic("enter_forked_process returned (should not happen)\n");
}


int sys_fork(struct trapframe *ctf, pid_t *retval) {
  #if OPT_SYSCALLS
  struct trapframe *tf_child;
  struct proc *newp;
  int result;

  KASSERT(curproc != NULL);

  newp = proc_create_runprogram(curproc->p_name);
  if (newp == NULL) {
    return ENOMEM;
  }

  /* done here as we need to duplicate the address space 
     of thbe current process */
  as_copy(curproc->p_addrspace, &(newp->p_addrspace));
  if(newp->p_addrspace == NULL){
    proc_destroy(newp); 
    return ENOMEM; 
  }

  /* we need a copy of the parent's trapframe */
  tf_child = kmalloc(sizeof(struct trapframe));
  if(tf_child == NULL){
    proc_destroy(newp);
    return ENOMEM; 
  }
  memcpy(tf_child, ctf, sizeof(struct trapframe));

  /* TO BE DONE: linking parent/child, so that child terminated 
     on parent exit */

  result = thread_fork(
		 curthread->t_name, newp,
		 call_enter_forked_process, 
		 (void *)tf_child, (unsigned long)0/*unused*/);

  if (result){
    proc_destroy(newp);
    kfree(tf_child);
    return ENOMEM;
  }

  *retval = newp->p_pid;
  #endif
  
  return 0;
}

int 
sys_execv(const char *program, char ** args) {
  #if OPT_SYSCALLS
  struct addrspace *new_as;
  struct addrspace *old_as;
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;
    
  int i = 0;
  userptr_t argv = NULL;
  int argc = 0;
  //amount of memory left for arg strings
  int left = ARG_MAX;
  //length of a arg string
  int len = 0;
  //temp for old userspace location of string
  userptr_t oldptr;
  //temp for old userspace char
  char oldchar;
  //stack that stores old userspace locations of strings
  struct list * oldptr_stack;
  //stack that stores new userspace locations of strings
  struct list * newptr_stack;
  //kernel location of string
  char * kstring;
  //new userspace location of string
  userptr_t newstring;
    
	KASSERT(proc_getas() != NULL);
    
  char * progname = kmalloc(PATH_MAX);
  size_t actual;
  result = copyinstr((const_userptr_t) program, progname, PATH_MAX, &actual);
  if(result) {
      kfree(progname);
      return result;
  }
    
	/* Open the file. */
	result = vfs_open(progname, O_RDONLY, 0, &v);
  kfree(progname);
	if (result) {
		return result;
	}

	/* Create a new address space. */
	new_as = as_create();
	if (new_as == NULL) {
		vfs_close(v);
		return ENOMEM;
	}

	/* Switch to it and activate it. */
	old_as = proc_setas(new_as);
	as_activate();

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		vfs_close(v);
		return result;
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(new_as, &stackptr);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		return result;
	}
    
  if(args != NULL) {
    //get the old userspace's arg string pointers
    as_deactivate();
    proc_setas(old_as);
    as_activate();
    oldptr_stack = list_create();
    newptr_stack = list_create();
    while(true) {
      result = copyin((userptr_t) args+argc*sizeof(userptr_t), &oldptr, sizeof(userptr_t));
      
      if(result) {
          list_destroy(oldptr_stack);
          list_destroy(newptr_stack);
          proc_setas(new_as);
          as_deactivate();
          proc_setas(old_as);
          as_activate();
          as_destroy(new_as);
          return EFAULT;
      }
      
      if(oldptr == NULL)
          break;
      
      list_push_front(oldptr_stack, (void*)oldptr);
      
      argc++;
    }
      
    for(i = argc-1; i >= 0; i--) {
      // switch back to old as
      as_deactivate();
      proc_setas(old_as);
      as_activate();
      
      oldptr = (userptr_t) list_front(oldptr_stack);
      list_pop_front(oldptr_stack);
      
      // make sure string is valid and get length
      for(len = 1;; len++) {
        // make sure next char is in userspace
        result = copyin((userptr_t) oldptr+len-1, &oldchar, 1);
      
        if(result) {
          list_destroy(oldptr_stack);
          list_destroy(newptr_stack);
          proc_setas(new_as);
          as_deactivate();
          proc_setas(old_as);
          as_activate();
          as_destroy(new_as);
          return EFAULT;
        }
          
        if(oldchar == 0)
            break;
      }
      left -= len;
      if(left < 0) {
        list_destroy(oldptr_stack);
        list_destroy(newptr_stack);
        proc_setas(new_as);
        as_deactivate();
        proc_setas(old_as);
        as_activate();
        as_destroy(new_as);
        return E2BIG;
      }
      
      // kmalloc for kernel string
      kstring = kmalloc(len);
      if(kstring == NULL) {
        list_destroy(oldptr_stack);
        list_destroy(newptr_stack);
        proc_setas(new_as);
        as_deactivate();
        proc_setas(old_as);
        as_activate();
        as_destroy(new_as);
        return ENOMEM;
      }
      
      //copyin the string
      result = copyin((userptr_t) args[i], kstring, len);
      if(result) {
        list_destroy(oldptr_stack);
        list_destroy(newptr_stack);
        kfree(kstring);
        proc_setas(new_as);
        as_deactivate();
        proc_setas(old_as);
        as_activate();
        as_destroy(new_as);
        return result;
      }
        
      // switch back to new as
      proc_setas(new_as);
      as_activate();
      
      //allocate word-aligned space in the new stack
      stackptr -= (vaddr_t)(len/sizeof(void*)*sizeof(void*)+(len%sizeof(void*) == 0 ? 0 : sizeof(void*)));
      newstring = (userptr_t) stackptr;
      
      // copyout, and kfree
      result = copyout(kstring, newstring, len);
      kfree(kstring);
      if(result) {
        list_destroy(oldptr_stack);
        list_destroy(newptr_stack);
        as_deactivate();
        proc_setas(old_as);
        as_activate();
        as_destroy(new_as);
        return result;
      }
      
      // put copyout location at end of list to be written later
      list_push_front(newptr_stack, newstring);
    }
    list_destroy(oldptr_stack);
    
    // create argv in new userspace
    proc_setas(new_as);
    as_activate();
    stackptr -= (vaddr_t)((argc+1)*sizeof(char *));
    argv = (userptr_t) stackptr;
      
    //copyout new arg string ptr locations into the new argv
    for(i = 0; i < argc; i++) {
        newstring = list_front(newptr_stack);
        list_pop_front(newptr_stack);
        result = copyout(&newstring, argv+i*sizeof(userptr_t), sizeof(userptr_t));
        if(result) {
            list_destroy(newptr_stack);
            as_deactivate();
            proc_setas(old_as);
            as_activate();
            as_destroy(new_as);
            return result;
        }
    }
    //write null at end of argv
    newstring = NULL;
    copyout(&newstring, argv+argc*sizeof(userptr_t), sizeof(userptr_t));
    
    list_destroy(newptr_stack);
  }
    

	/* Destroy the old address space. */
  proc_setas(old_as);
  as_deactivate();
  proc_setas(new_as);
  as_activate();
	as_destroy(old_as);

	/* Warp to user mode. */
	enter_new_process(argc, (userptr_t) argv,
			  NULL /*userspace addr of environment*/,
			  stackptr, entrypoint);

	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL;
  #endif

  return 0;
}

int
sys_getcwd(userptr_t buf_ptr, size_t size, int *retval) {
    #if OPT_SYSCALLS

    struct iovec iov;
    struct uio u;
    int result;

    iov.iov_ubase = buf_ptr;
    iov.iov_len = size;

    u.uio_iov = &iov;
    u.uio_iovcnt = 1;
    u.uio_resid = size;          // amount to read from the file
    u.uio_offset = 0;
    u.uio_segflg =UIO_USERISPACE;
    u.uio_rw = UIO_READ;
    u.uio_space = curproc->p_addrspace;


    result = vfs_getcwd(&u);
    if (result) {
      return result;
    }

    *retval = size - u.uio_resid;;

    return 0;

    #endif
    
    return 0;
}

int
sys_chdir(const char *path) {
    #if OPT_SYSCALLS

    char * mypath = kmalloc(strlen(path));
    strcpy(mypath, path);
    int result = vfs_chdir(mypath);
    return result;

    #endif

    return 0;
}
