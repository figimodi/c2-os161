# PROC HANDLING SYSCALLS
For each of the reported system calls, we will report the code and an brief explanation of the latter. While providing the explenation of the depicted code, we will also analize some design choices.

## execv
```
int 
sys_execv(userptr_t program, userptr_t * args) {

    struct addrspace *new_as;
    struct addrspace *old_as;

    struct vnode *v;
  
	vaddr_t entrypoint, stackptr;
    
    int i = 0, result, length, tail, arg_length = 0, argc = 0;

    int * stackargs;
    volatile userptr_t currptr;

	KASSERT(proc_getas() != NULL);
    
    /* Copying the file path into kernel memory */
    char * progname = kmalloc(PATH_MAX);
    size_t actual;
    result = copyinstr((const_userptr_t) program, progname, PATH_MAX, &actual);
    if(result) {
        /* Error handling not reported, check the code */
    }
    
	/* Open the file. */
	result = vfs_open(progname, O_RDONLY, 0, &v);
    kfree(progname);
    if (result) {
        return EACCES;
    }

	/* Create a completely new address space */

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
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(new_as, &stackptr);
	if (result) {
		return result;
	}
    
    if(args != NULL) {
        
        /* Go back to previous address space to get parameters */
        as_deactivate();
        proc_setas(old_as);
        as_activate();

        /* Find args size and total length */
        for(i=0; args[i]!=NULL; i++, argc++){
        arg_length += strlen((char*)args[i]);
        }

        if(arg_length > ARG_MAX){
        kprintf("Argments are too big. Max total size is %d\n", ARG_MAX);
        return E2BIG;
        }


        /*
        Need to save each argument into a kernel buffer so that we can then later move them into a new userptr
        */

        char ** kargs =kmalloc(argc * sizeof(char *));

        if(kargs == NULL){
        return ENOMEM;
        }

        for(i=0; i<argc; i++){
        kargs[i] = kmalloc(128);
        if (kargs[i] == NULL){
            /* Error handling not reported, check the code */
        }
        }

        for(i=0; i<argc; i++){
        /* Save into kargs[i] the all the arguments*/
        /* Hope we fit */
        result = copyinstr((userptr_t)args[i], kargs[i], 128, &actual);
        if(result){
            /* Error handling not reported, check the code */
        }
        }

        stackargs = (int*)kmalloc((argc+1) * sizeof(int *));

        if(stackargs == NULL){
            /* Error handling not reported, check the code */
        }

        
        as_deactivate();
        proc_setas(new_as);
        as_activate();

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
                /* Error handling not reported, check the code */
            }

            kfree(kargs[i]);

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
                /* Error handling not reported, check the code */
                }
            }

        kfree(stackargs);

        as_destroy(old_as);

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

  return 0;
}

```
The goal of the execv system call is the substitution of the running program, with another one passed as parameter to the function. We start of by saving in kernel memory the program path parameter. Once done that we can go on and open the file to get the executable code. A new address space is created so that it can substitute the current one. After loading the ELF file in the newly created address space we move on to the handling of parameters passed to the system call. This part of the implementation resulted very tedious and attention worth.  At the very beginning we started with the very simple task of counting the arguments passed. After switching to the old address space and counting the arguments, we went along to copy those arguments from the old address space to kernel memory. To save them in the kernel we used the dynamically allocated array ```kargs```. After moving the arguments in the kernel, we proceded by moving them in the new address space. Starting from the address ```stackptr```, each parameter was saved in memory, always respecting the world allignment of the stack. While saving each argument, a kernel support array was filled with their new address in the new address space. After copying all of them, we proceded by copying also the address in memory. Once done this it was possible to call the function ```enter_new_process``` and switch to the new program.

## fork
```
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

    // link child to parent process
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
    
    return 0;
```

The implementation of the fork syscall is left more or less the same of the one provided in the labs, except for the addition of parent and child process linking. After creating the new process, the parent pid is saved in the the ```pp_pid``` variable stored in the proc struct. This linking will be useful when calling waitpid or exit. 

## waitpid
```
struct proc *p;
  int s;
  pid_t c_pid;
  
  // only option allowed is WNOHANG
  if((options & !WNOHANG) != 0){
    // other options were passed! must abort
    if (statusp!=NULL) 
          *(int*)statusp = EINVAL;
      return -1;
  }

  if(pid < -1 || pid == 0){
    kprintf("waiting on groups not implemeted yet!");
    if (statusp!=NULL) 
          *(int*)statusp = EINVAL;
      return -1;

  }else if(pid == -1){
    // need to wait for any child process
    // to do this we will add a semaphore initialized to 0 so that the process will wait
    // any child process that will terminate will then post the the semaphore so that the parent will wake
    // when the parent process wakes it will go through all of it's children to check if they are terminated
    // and will see their return values.

    if(proc_count_children(curproc->p_pid) ==  0){
      if (statusp!=NULL) 
          *(int*)statusp = ECHILD;
      return -1;
    }
    if(options & WNOHANG){
      // need to check if any child has finished
      if(curproc->exited_children == 0){
        return 0;
      }
    }

    P(curproc->waiting_sem);
    // need to find any child process and get the termination;
    for(int j=1; j<PID_MAX; j++){
      p = proc_search_pid(j);
      if(p->pp_pid == curproc->p_pid && p->p_exited == 1){
        // found the child process
        c_pid = p->p_pid;

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
    // if i get here i couldnt find the child process that terminated.
    return -1;
  }else{
    // need to wait for a specific process
    p = proc_search_pid(pid);
    int s;
    (void)options; /* not handled */
    if (p==NULL) return -1;

    if((options & WNOHANG) && p->p_exited == 0){
      return 0;
    }

    s = proc_wait(p);
    if (statusp!=NULL) 
      *(int*)statusp = s;
    return pid;
  }
```

Our choices for the waitpid were to only allow as an option ```WNOHANG``` and as pid either -1 (waiting for any child) or > 1 (waiting for a specific process). After checking that out constraints were met, the system call goes along in conditional execution depending on the value of pid.

To help the support of waiting for any child, some additions were made to out data structures. Following reported is the process struct.
```
struct proc {
	char *p_name;			/* Name of this process */
	struct spinlock p_lock;		/* Lock for this structure */
	unsigned p_numthreads;		/* Number of threads in this process */

	/* VM */
	struct addrspace *p_addrspace;	/* virtual address space */

	/* VFS */
	struct vnode *p_cwd;		/* current working directory */

	int p_status;                   /* status as obtained by exit() */
	int p_exited;
	int exited_children;

	pid_t p_pid;
	pid_t pp_pid;

	struct semaphore *p_sem;
	struct semaphore *waiting_sem;
	struct openfile *fileTable[OPEN_MAX];

}
```

Each process has a flag ```p_exited``` which is set to one when exit is called by the process and a counter ```exited_children``` that is incremented every time a child process terminates. A new semaphore, ```waiting_sem```, was also added; every time a process must wait for one of his children, it will wait on this semaphore.

### pid = -1
The current process must wait for any child termination. If the process does not have any child an error ```ECHILD``` is set. If the option ```WNOHANG``` is set and no child has exited (checked through ```exited_children```) the function returns immediatly. We then wait on ```waiting_sem``` and when we wake up we check which of out child processes was responsible for our awakening. After identifying it, we wait on its semaphore ```p_sem``` so that the target proc will be destroyed afterwards. 

### pid > 1
The current process must wait for a specific process. To do this the current process will wait on the semaphore ```p_sem```
of the desired proc. If the option ```WNOHANG``` is set, and the target process has not exited ```p_exited == 0```, the syscall will return immediatly.

## exit
```
    struct proc *p = curproc;
    struct proc *parent_p;

    p->p_status = status & 0xff; /* just lower 8 bits returned */
    p->p_exited = 1;
    proc_remthread(curthread);

    V(p->p_sem);

    // need to post also the parent process child semaphore
    if(p->pp_pid != 0){
        parent_p = proc_search_pid(p->pp_pid);

        if(parent_p == NULL || parent_p->p_exited){
            // parent has exited so we can completely wipe out the current process data.
            proc_destroy(p);
    }else{
        // parent is still alive so we need to let him know we finished
        // mutual exclusion to increase the number of children
        spinlock_acquire(&(parent_p->p_lock));
        parent_p->exited_children ++;
        spinlock_release(&(parent_p->p_lock));
        
        V(parent_p->waiting_sem);
        }
    }
    thread_exit();
    panic("thread_exit returned (should not happen)\n");
```

When calling this syscall, the process will end its execution. We start by setting the ```p_status``` and the flag ```p_exited``` in the current process struct. We post the semaphore ```p_sem``` and after that, we check if the currproc has a parent process. If it does have a parent process, we first check if the parent has already terminated. If the answer is positive we can go ahead and destroy the current process. If the parent is still active we need to signal to it our termination. We do this by increasing its children exits and by posting the semaphore ```waiting_sem```. Finally we call the function ```thread_exit``` to switch to another thread.
