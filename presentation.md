# PROC HANDLING SYSCALLS

## getcwd
```c
int
sys_getcwd(userptr_t buf_ptr, size_t size, int *retval) {

    if(buf_ptr==NULL)
      return EFAULT;

    if(size == 0 && buf_ptr!=NULL)
     return EINVAL;

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

    int l = size - u.uio_resid;

    if(l<(int)strlen((char *)buf_ptr)) {
      return ERANGE;
    }
    
    *retval = l;

    return result;
}

```
```getcwd``` allows to store the path to the current working directory as a string.
We first run some initial checks on the passed parameters: if there are some anomalies we return the proper error code.
After that, through ```vfs_getcwd```, we get the current working directory and save it directly in the memory area pointed by the pointer passed as argument. We check the return value in case of any error is returned by this opearation.

## chdir
```c
int
sys_chdir(const char *path) {
    int result = 0;

    if (path == NULL)
      return EFAULT;

    if(strlen(path)==0)
      return ENOENT;

    char * kbuf = kmalloc(strlen(path));
    if (kbuf==NULL)
      return ENOMEM;

    result = copyinstr((const_userptr_t)path, kbuf, strlen(path) + 1, NULL);
    if (result) {
      kfree(kbuf);
      return result;
    }

    struct vnode *v;
    result = vfs_open((char *)kbuf, O_RDONLY, 0, &v);

    if(result) {
      kfree(kbuf);
      return result;
    }

    result = vfs_chdir(kbuf);

    kfree(kbuf);
    return result;
}

```
```chdir``` allows to change the current working directory to the one passed as argument.
We first run some initial checks on the passed parameters: if there are some anomalies we return the proper error code (for example NULL path name passed as parameter).
After that we allocate a kernel buffer and check for its correct allocation. Then we copy into it, through ```copyinstr```, the string passed as argument always checking for its correct execution. Then we check if the path is valid through ```vfs_open``` and finally trough ```vfs_chdir``` we change the directory and as usual check for any error. 

## dup2
```c
int sys_dup2(int oldfd, int newfd, int *errp) {
  if (newfd<STDERR_FILENO || newfd>OPEN_MAX) { *errp=EBADF; return -1; }
  if (oldfd<STDERR_FILENO || oldfd>OPEN_MAX || curproc->fileTable[oldfd]==NULL) { *errp=EBADF; return -1; }
  if (oldfd==newfd) return newfd;

  if(curproc->fileTable[newfd] != NULL){
    // close the file for this process
    sys_close(newfd);
  }

  if(curproc->fileTable[oldfd] == NULL) {
    return EBADF;
  }

  struct openfile *of = curproc->fileTable[oldfd];
  curproc->fileTable[newfd] = of;
  openfileIncrRefCount(of);

  return newfd;
}
```
```dup2``` allows to create a new file descriptor that refers to the open file decscription of a descriptor passed as parameter.
We initially check if old and new file descriptors are valid and then we save into the file table at position newFD the pointer to the openfile structure saved into the file table at oldFD.