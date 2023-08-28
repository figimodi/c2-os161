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
#include <kern/wait.h>
#include <kern/stat.h>
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
  struct proc *parent_p;

  /* Save status and set exited flag */
  p->p_status = status & 0xff; /* just lower 8 bits returned */
  p->p_exited = 1;
  proc_remthread(curthread);

  V(p->p_sem);

  /* If process has a parent, need to signal it */
  if(p->pp_pid != 0){
    parent_p = proc_search_pid(p->pp_pid);

    if(parent_p == NULL || parent_p->p_exited){
      /* Parent has already been waited on and is now destroied or has called exit */
      proc_destroy(p);
    
    }else{
      
      /* Parent is still alive so increment exited children counter */
      spinlock_acquire(&(parent_p->p_lock));
      parent_p->exited_children ++;
      spinlock_release(&(parent_p->p_lock));
      
      /* Post its semaphore for child waiting */
      V(parent_p->waiting_sem);
    }
  }
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
  struct proc *p;
  int s;
  pid_t c_pid;
  
  /* Only option allowed is WNOHANG */
  if((options & !WNOHANG) != 0){
    // other options were passed! must abort
    if (statusp!=NULL) 
          *(int*)statusp = EINVAL;
      return -1;
  }

  /* Can only wait for specific pid or for any child */
  if(pid < -1 || pid == 0){
    kprintf("Waiting on groups not implemeted yet!");
    if (statusp!=NULL) 
          *(int*)statusp = EINVAL;
      return -1;

  }else if(pid == -1){
    /* Waiting for any child process */

    /* Return error if the calling process does not have any child */
    if(proc_count_children(curproc->p_pid) ==  0){
      if (statusp!=NULL) 
          *(int*)statusp = ECHILD;
      return -1;
    }

    if(options & WNOHANG){
      /* Will simply check the counter in the process struct*/
      if(curproc->exited_children == 0){
        return 0;
      }
    }

    /* This call wont block because at least a child has exited */
    P(curproc->waiting_sem);

    /* Detect which child pid has exited */
    for(int j=1; j<PID_MAX; j++){
      p = proc_search_pid(j);
      if(p->pp_pid == curproc->p_pid && p->p_exited == 1){
        /* Child found */
        c_pid = p->p_pid;

        /* Call proc_wait on the child so that it will be destroied */
        s = proc_wait(p);
        if (statusp!=NULL) 
          *(int*)statusp = s;
        
        /* decrease the children exited count */
        spinlock_acquire(&(curproc->p_lock));
        curproc->exited_children --;
        spinlock_release(&(curproc->p_lock));

        return c_pid;
      }
    }
    
    /* I couldnt find the child that terminated so will return error */
    if (statusp!=NULL) 
      *(int*)statusp = ECHILD;
    return -1;

  }else{
    
    /* Waiting on a specific process */
    p = proc_search_pid(pid);
    int s;

    if (p==NULL) return -1;

    /* If option is WNOHANG and p has not yet exited */
    if((options & WNOHANG) && p->p_exited == 0){
      return 0;
    }

    s = proc_wait(p);
    if (statusp!=NULL) 
      *(int*)statusp = s;
    return pid;
  }
#else
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
     of the current process */
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

  /* Link child to parent process */
  newp->pp_pid = curproc->p_pid;

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

/* Frees args[i] up to i = argc - 1 and then frees args */
static void kfree_kargs(char ** args, int argc){
  for(int i=0; i<argc; i++){
    kfree(args[i]);
  }
  kfree(args);
}

int 
sys_execv(userptr_t program, userptr_t * args) {
  #if OPT_SYSCALLS
  struct addrspace *new_as;
  struct addrspace *old_as;

	struct vnode *v;

	vaddr_t entrypoint, stackptr;
    
  int result, length, tail, arg_length = 0, i = 0, argc = 0;

  volatile userptr_t currptr;
  //userptr_t argv = NULL;

  int * stackargs;
  
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
		return EACCES;
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
		vfs_close(v);
		return EACCES;
    /* Go back to initial addres space and destroy new one */
    as_deactivate();
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(new_as, &stackptr);
	if (result) {
    /* Go back to initial addres space and destroy new one */
    as_deactivate();
    proc_setas(old_as);
    as_activate();
    as_destroy(new_as);
		return result;
	}

 /* Both entry point and stack are now set for the new address space */
    
  if(args != NULL) {
    /*
      We now need to get all the arguments that were passed in
      the previous address space and store them in the new address space
    */

    as_deactivate();
    proc_setas(old_as);
    as_activate();

    /* Counting args */
    for(i=0; args[i]!=NULL; i++, argc++){
      arg_length += strlen((char*)args[i]);
    }

    /* Check max size */
    if(arg_length > ARG_MAX){
      kprintf("Argments are too big. Max total size is %d\n", ARG_MAX);
      return E2BIG;
    }

    /* Save args in kernel buffers */
    char ** kargs =kmalloc(argc * sizeof(char *));

    if(kargs == NULL){
      as_destroy(new_as);
      return ENOMEM;
    }

    for(i=0; i<argc; i++){
      kargs[i] = kmalloc(128);
      if (kargs[i] == NULL){
        kprintf("Couldn't allocate memory in kernel for argument passing\n");
        kfree_kargs(kargs, i-1);
        as_destroy(new_as);
        return ENOMEM;
      }
    }

    /* Save into kargs[i] the user argument args[i] */

    for(i=0; i<argc; i++){
      /* Hope we fit */
      result = copyinstr((userptr_t)args[i], kargs[i], 128, &actual);
      if(result){
        kprintf("Copy argument from user to kernel did not work. Aborting\n");
        kfree_kargs(kargs, argc);
        as_destroy(new_as);
        return result;
      }
    }

    stackargs = (int*)kmalloc((argc+1) * sizeof(int *));

    if(stackargs == NULL){
      kprintf("Couldnt allocate memory in kernel to save new addresses. Aborting\n");
      kfree_kargs(kargs, argc);
      as_destroy(new_as);
      return ENOMEM;
    }

    /* Move to new address space */
    as_deactivate();
    proc_setas(new_as);
    as_activate();
  
    /* Copying all arguments in userspace starting from address stackptr */
    currptr = (userptr_t)stackptr;
    for (i = 0; i < argc ; i++){
      
      /* Consider space for string termination */
      length = strlen(kargs[i]) + 1;

      /* Check allignment in the stack */
      currptr -= length;
      tail = 0;

      if((int)currptr & 0x3){
        tail = (int)currptr & 0x3;
        currptr -= tail;
      }

      /* Copy from kernel to user memory */
      result = copyout(kargs[i], (userptr_t)currptr, length);

      if (result) {
        kprintf("Couldnt copy argv[%d] from kernel to new user space\n", i);
        kfree_kargs(kargs, argc);
        kfree(stackargs);
        as_deactivate();
        proc_setas(old_as);
        as_activate();
        as_destroy(new_as);
        return result;
      }

      kfree(kargs[i]);

      /* Store the address in userspace of the current arg */
      stackargs[i] = (int)currptr;
    }

    kfree(kargs);

    /* Last arg must be null pointer */
    stackargs[i] = 0;

    /* Save in memory the new argv (pointers to arguments) */
    for (i=argc; i>=0; i--){
      currptr -= sizeof(char *);
      result = copyout(stackargs + i, currptr, sizeof(char*));

      if(result){
        kprintf("Sorry, couldnt copy address of parameter from kernel to userspace\n");
        kfree(stackargs);
        as_deactivate();
        proc_setas(old_as);
        as_activate();
        as_destroy(new_as);
        return result;
      }
    }

    kfree(stackargs);

    enter_new_process(argc, (userptr_t)currptr,
			  NULL /*userspace addr of environment*/,
			  (vaddr_t)currptr, entrypoint);
  }else{

    /* No arguments were passed */
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
sys_getcwd(userptr_t buf_ptr, size_t size, int *errp) {
    #if OPT_SYSCALLS
    int result=0;

    if(buf_ptr==NULL) {
      *errp = EFAULT;
      return result;
    }

    if(size == 0 && buf_ptr!=NULL) {
      *errp = EINVAL;
      return result;
    }

    struct iovec iov;
    struct uio u;

    iov.iov_ubase = buf_ptr;
    iov.iov_len = size;

    u.uio_iov = &iov;
    u.uio_iovcnt = 1;
    u.uio_resid = size;          // amount to read from the file
    u.uio_offset = 0;
    u.uio_segflg =UIO_USERISPACE;
    u.uio_rw = UIO_READ;
    u.uio_space = curproc->p_addrspace;

    *errp = vfs_getcwd(&u);
    if (*errp) {
      return result;
    }

    result = size - u.uio_resid;

    if(result<(int)strlen((char *)buf_ptr)) {
      *errp = ERANGE;
      return result;
    }

    return result;

    #endif
    
    return 0;
}

int
sys_chdir(const char *path, int *errp) {
    #if OPT_SYSCALLS

    int result = 0;

    if(path==NULL) {
      *errp = EFAULT;
      return result;
    }

    if(strlen(path)==0) {
      *errp = ENOENT;
      return result;
    }

    char * kbuf = kmalloc(strlen(path));
    if (kbuf==NULL) {
      *errp = ENOMEM;
      return result;
    }

    *errp = copyinstr((const_userptr_t)path, kbuf, strlen(path) + 1, NULL);
    if (*errp) {
      kfree(kbuf);
      return result;
    }

    struct vnode *v;
    *errp = vfs_open((char *)kbuf, O_RDONLY, 0, &v);

    if(*errp) {
      kfree(kbuf);
      return result;
    }

    *errp = vfs_chdir(kbuf);

    kfree(kbuf);
    return result;

    #endif

    return 0;
}