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

pid_t
sys_getppid(void)
{
#if OPT_SYSCALLS
  KASSERT(curproc != NULL);
  return curproc->pp_pid;
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
sys_execv(userptr_t program, userptr_t * args) {
  #if OPT_SYSCALLS
  struct addrspace *new_as;
  struct addrspace *old_as;

	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;
    
  int i = 0, length, tail;

  volatile userptr_t currptr;
  //userptr_t argv = NULL;

  int * stackargs;
  
  int argc = 0;
  
	KASSERT(proc_getas() != NULL);
    
  char * progname = kmalloc(PATH_MAX);
  size_t actual;
  result = copyinstr((const_userptr_t) program, progname, PATH_MAX, &actual);
  if(result) {
      // couldn't get the program name from the userspace
      kfree(progname);
      return result;
  }
    
	/* Open the file. */
	result = vfs_open(progname, O_RDONLY, 0, &v);
  // do not need the name of the program anymore
  kfree(progname);
	if (result) {
    // couldn't open the file to execute
		return result;
	}

	/* Create a new address space. Not a copy of the old one but a completely new as*/

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

  // both entry point and stack are now set for the new address space.
    
  if(args != NULL) {
    /*
      We now need to get all the arguments that were passed in
      the previous address space and store them in the new address space
    */
   // first we need to identify the number of parameters that were passed

    as_deactivate();
    proc_setas(old_as);
    as_activate();

    for(i=0; args[i]!=NULL; i++, argc++);

    /*
      Need to save each argument into a kernel buffer so that we can then later move them into a new userptr

    */

    char ** kargs =kmalloc(argc * sizeof(char *));

    stackargs = (int*)kmalloc((argc+1) * sizeof(int *));

    if(kargs == NULL){
      kprintf("Not enoguh memory in kernel to move arguments :(\n");
      return ENOMEM;
      // TODO? forse solo return ENOMEM oppure panic("I don't know how to handle this\n");
    }

    for(i=0; i<argc; i++){
      /* Save into kargs[i] the new */
      /* Hope we fit */
      kargs[i] = kmalloc(128);
      result = copyinstr((userptr_t)args[i], kargs[i], 128, &actual);
      if(result){
        kprintf("Copy argument did not work correctly\n");
      }

    }

    // all the arguments have been saved and the path has already been used so we can get rid of the old address space
    
    as_deactivate();
    proc_setas(new_as);
    as_activate();
    as_destroy(old_as);

    // now I need to copy all these parameters in the new address space.

    // starting from the new stackptr
    currptr = (userptr_t)stackptr;
    for (i = 0; i < argc ; i++){
      // need to copy in the stack kargs[i];
      // length must be incremented by one to consider the string termination character;
      length = strlen(kargs[i]) + 1;

      // need to make sure that we are still alligned in the stack
      currptr -= length;
      tail = 0;

      if((int)currptr & 0x3){
        // not alligned!
        tail = (int)currptr & 0x3;

        // will now subtract the tail to be at the beginning of the word
        currptr -= tail;
      }

      // need to copy from kernel memory to user memory
      result = copyout(kargs[i], (userptr_t)currptr, length);

      if (result) {
        kprintf("Couldnt copy argvù[%d] from kernel to new user space\n", i);
      }
      kfree(kargs[i]);


      // do I need to zero out memory that is not copied? might already be zeroed out. check with debug
      
      stackargs[i] = (int)currptr;
    }

    kfree(kargs);

    // last arguments must be null pointer
    stackargs[i] = 0;

    // need to save in memory also the pointers to the arguments in user memory;

    for (i=argc; i>=0; i--){
      currptr -= sizeof(char *);
      result = copyout(stackargs + i, currptr, sizeof(char*));

      if(result){
        kprintf("Sorry, couldnt copy address of argv :(\n");
      }
    }

    kfree(stackargs);

    enter_new_process(argc, (userptr_t)currptr,
			  NULL /*userspace addr of environment*/,
			  (vaddr_t)currptr, entrypoint);
  }else{
    // no arguments were passed!
    as_deactivate();
    proc_setas(new_as);
    as_activate();
    as_destroy(old_as);

	/* Warp to user mode. */
	enter_new_process(0, NULL,
			  NULL /*userspace addr of environment*/,
			  stackptr, entrypoint);
  }
  


	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL;

  #endif
  return 0;
}

int
sys_getcwd(userptr_t buf_ptr, size_t size, int *retval) {
    #if OPT_SYSCALLS

    if(buf_ptr==NULL)
      return EFAULT;

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

// int
// sys_chdir(const char *path) {
//     #if OPT_SYSCALLS

//     if (path == NULL)
//       return EFAULT;

//     char * mypath = kmalloc(strlen(path));
//     strcpy(mypath, path);
//     int result = vfs_chdir(mypath);
//     return result;

//     #endif

//     return 0;
// }

int
sys_chdir(const char *path) {
    #if OPT_SYSCALLS

    int result = 0;

    if (path == NULL)
      return EFAULT;

    char * mypath = kmalloc(strlen(path));
    if (mypath==NULL)
      return EFAULT;

    result = copyinstr((const_userptr_t)path, mypath, strlen(path) + 1, NULL);
    if (result) 
    {
      kfree(mypath);
      return result;
    }
    
    result = vfs_chdir(mypath);
    // struct vnode *newcwd;
    // result = vfs_open(mypath, O_RDONLY, 0, &newcwd);
    // if (result)
    // {
    //   kfree(mypath);
    //   return result;
    // }

    // struct vnode *oldcwd;
    // oldcwd = curproc->p_cwd;
    // curproc->p_cwd = newcwd;

    // vfs_close(oldcwd);
    // kfree(mypath);

    return result;

    #endif

    return 0;
}