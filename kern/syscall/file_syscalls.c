/*
 * AUthor: G.Cabodi
 * Very simple implementation of sys_read and sys_write.
 * just works (partially) on stdin/stdout
 */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <kern/seek.h>
#include <kern/fcntl.h>
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
#include <stat.h>
#include <synch.h>


/* max num of system wide open files */
#define SYSTEM_OPEN_MAX (10*OPEN_MAX)

#define USE_KERNEL_BUFFER 0

struct rwlock {
  int n_read_active; /* integer representing the number of readers currently reading on the file */
  int write_active; /* boolean */
  struct lock *mutex; /* the lock used for the condition variable and other critical sections */
  struct cv *cv; /* condition variable to avoid busy waiting */
};

/* system open file table */
struct openfile {
  struct vnode *vn;
  off_t offset;	
  unsigned int countRef;
  off_t size;
  uint32_t openflags;
  struct rwlock rwlock;
};

struct openfile systemFileTable[SYSTEM_OPEN_MAX];

void openfileIncrRefCount(struct openfile *of) {
  if (of!=NULL)
  {
    lock_acquire((of->rwlock).mutex);
    of->countRef++;
    lock_release((of->rwlock).mutex);
  }
}

#if USE_KERNEL_BUFFER

static int
file_read(int fd, userptr_t buf_ptr, size_t size) {
  struct iovec iov;
  struct uio ku;
  int result, nread;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0||fd >= OPEN_MAX) return -1;
  of = curproc->fileTable[fd];
  if (of == NULL) return -1;
  vn = of->vn;
  if (vn == NULL) return -1;

  kbuf = kmalloc(size);
  uio_kinit(&iov, &ku, kbuf, size, of->offset, UIO_READ);
  result = VOP_READ(vn, &ku);
  if (result) {
    return result;
  }
  of->offset = ku.uio_offset;
  nread = size - ku.uio_resid;
  copyout(kbuf,buf_ptr,nread);
  kfree(kbuf);
  return (nread);
}

static int
  file_write(int fd, userptr_t buf_ptr, size_t size) {
  struct iovec iov;
  struct uio ku;
  int result, nwrite;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd >= OPEN_MAX) return -1;
  of = curproc->fileTable[fd];
  if (of == NULL) return -1;
  vn = of->vn;
  if (vn == NULL) return -1;

  kbuf = kmalloc(size);
  copyin(buf_ptr,kbuf,size);
  uio_kinit(&iov, &ku, kbuf, size, of->offset, UIO_WRITE);
  result = VOP_WRITE(vn, &ku);
  if (result) {
    return result;
  }
  kfree(kbuf);
  of->offset = ku.uio_offset;
  nwrite = size - ku.uio_resid;
  return (nwrite);
}

#else

static int
file_read(int fd, userptr_t buf_ptr, size_t size) {
  #if OPT_SYSCALLS
  struct iovec iov;
  struct uio u;
  
  int result;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd >= OPEN_MAX) return -1;
  of = curproc->fileTable[fd];
  if (of == NULL) return -1;
  vn = of->vn;
  if (vn == NULL) return -1;

  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;          // amount to read from the file
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_READ;
  u.uio_space = curproc->p_addrspace;

  result = VOP_READ(vn, &u);
  if (result) {
    return result;
  }

  of->offset = u.uio_offset;
  return (size - u.uio_resid);
  #endif
}

static int
file_write(int fd, userptr_t buf_ptr, size_t size) {
  #if OPT_SYSCALLS
  struct iovec iov;
  struct uio u;
  int result;
  struct vnode *vn;
  struct openfile *of;

  if (fd < 0 || fd >= OPEN_MAX) return -1;
  of = curproc->fileTable[fd];
  if (of == NULL) return -1;
  vn = of->vn;
  if (vn == NULL) return -1;

  iov.iov_ubase = buf_ptr;
  iov.iov_len = size;

  u.uio_iov = &iov;
  u.uio_iovcnt = 1;
  u.uio_resid = size;          // amount to read from the file
  u.uio_offset = of->offset;
  u.uio_segflg =UIO_USERISPACE;
  u.uio_rw = UIO_WRITE;
  u.uio_space = curproc->p_addrspace;

  result = VOP_WRITE(vn, &u);
  if (result) {
    return result;
  }

  of->offset = u.uio_offset;
  return (size - u.uio_resid);
  #endif
}

#endif

/*
 * file system calls for open/close
 */
int
sys_open(userptr_t path, int openflags, mode_t mode, int *errp)
{
  #if OPT_SYSCALLS
  int fd, i;
  struct vnode *v;
  struct openfile *of=NULL;; 	
  int result;

  result = vfs_open((char *)path, openflags, mode, &v);
  if (result) {
    *errp = ENOENT;
    return -1;
  }

  struct stat statbuf;
  result = VOP_STAT(v, &statbuf);
  if (result) {
    *errp = ENOENT;
    return -1;
  }

  /* search system open file table */
  for (i=0; i < SYSTEM_OPEN_MAX; i++) {
    if (systemFileTable[i].vn==NULL) {
      of = &systemFileTable[i];
      of->vn = v;
      of->countRef = 1;
      of->size = statbuf.st_size;
      if (openflags & O_APPEND) 
        of->offset = of->size;
      else
        of->offset = 0;
      of->openflags = openflags;
      (of->rwlock).mutex = lock_create("file_lock");
      (of->rwlock).cv = cv_create("file_cv");
      (of->rwlock).n_read_active = 0;
      (of->rwlock).write_active = 0;
      break;
    }
  }
  if (of==NULL) { 
    // no free slot in system open file table
    *errp = ENFILE;
  }
  else {
    for (fd = STDERR_FILENO + 1; fd < OPEN_MAX; fd++) {
      if (curproc->fileTable[fd] == NULL) {
        curproc->fileTable[fd] = of;
        return fd;
      }
    }
    // no free slot in process open file table
    *errp = EMFILE;
  }
  
  vfs_close(v);
  #endif

  return -1;
}

/*
 * file system calls for open/close
 */
int
sys_close(int fd, int *errp)
{
  #if OPT_SYSCALLS
  struct openfile *of=NULL; 
  struct vnode *vn;

  if (fd < 0 || fd >= OPEN_MAX)
  {
    *errp = EBADF;
    return -1;
  }

  of = curproc->fileTable[fd];
  if (of == NULL)
  {
    *errp = EBADF;
    return -1;
  }

  curproc->fileTable[fd] = NULL;
  if (--of->countRef > 0) return 0; // just decrement ref cnt
  
  vn = of->vn;
  of->vn = NULL;
  lock_destroy((of->rwlock).mutex);
  cv_destroy((of->rwlock).cv);
  if (vn==NULL) return -1;

  vfs_close(vn);		

  return 0;
  #endif

  return 0;
}

/*
 * simple file system calls for write/read
 */
int
sys_write(int fd, userptr_t buf_ptr, size_t size, int *errp)
{
  #if OPT_SYSCALLS
  int i, result, file_mode;
  off_t recovery_offset;
  char *p = (char *)buf_ptr;

  if (fd!=STDOUT_FILENO && fd!=STDERR_FILENO) 
  {
    struct openfile *of = curproc->fileTable[fd];
    file_mode = of->openflags & O_ACCMODE;
    recovery_offset = of->offset;

    /* checking if the file was opend with the right mode */
    if (file_mode == O_RDONLY)
    {
      *errp = EBADF;
      return -1;
    }

    lock_acquire((of->rwlock).mutex);
    while((of->rwlock).n_read_active > 0 || (of->rwlock).write_active == 1)
      cv_wait((of->rwlock).cv, (of->rwlock).mutex);

    (of->rwlock).write_active = 1;
    lock_release((of->rwlock).mutex);

    /* when O_APPEND is set, before every write the cursor should be moved at the end */
    if (of->openflags & O_APPEND)
      sys_lseek(fd, 0, SEEK_END, &result);
    if (result)
    {
      *errp = ENOSYS;
      lock_acquire((of->rwlock).mutex);
      (of->rwlock).write_active = 0;
      cv_broadcast((of->rwlock).cv, (of->rwlock).mutex);
      lock_release((of->rwlock).mutex);
      return -1;
    }
    result = file_write(fd, buf_ptr, size);
    if (result)
    {
      /* set back the original offset (atomic operation in case of O_APPEND)*/
      sys_lseek(fd, recovery_offset, SEEK_SET, &result);
      *errp = ENOSYS;
      lock_acquire((of->rwlock).mutex);
      (of->rwlock).write_active = 0;
      cv_broadcast((of->rwlock).cv, (of->rwlock).mutex);
      lock_release((of->rwlock).mutex);
      return -1;
    }
    lock_acquire((of->rwlock).mutex);
    (of->rwlock).write_active = 0;
    cv_broadcast((of->rwlock).cv, (of->rwlock).mutex);
    lock_release((of->rwlock).mutex);
    return result;
  }

  for (i=0; i<(int)size; i++) {
    putch(p[i]);
  }

  return (int)size;
  #endif

  return 0;
}

int
sys_read(int fd, userptr_t buf_ptr, size_t size, int *errp)
{
  #if OPT_SYSCALLS
  int i;
  int result;
  int file_mode;
  char *p = (char *)buf_ptr;
  struct openfile *of;

  if (size == 0)
    return 0;

  if (fd!=STDIN_FILENO)
  {
    of = curproc->fileTable[fd];
    file_mode = of->openflags & O_ACCMODE;

    if (file_mode == O_WRONLY)
    {
      *errp = EBADF;
      return -1;
    }
    
    lock_acquire((of->rwlock).mutex);
    while((of->rwlock).write_active == 1)
      cv_wait((of->rwlock).cv, (of->rwlock).mutex);

    (of->rwlock).n_read_active++;
    lock_release((curproc->fileTable[fd]->rwlock).mutex);

    result = file_read(fd, buf_ptr, size);

    lock_acquire((of->rwlock).mutex);
    (of->rwlock).n_read_active--;
    if ((of->rwlock).n_read_active == 0)
      cv_broadcast((of->rwlock).cv, (of->rwlock).mutex);
    lock_release((curproc->fileTable[fd]->rwlock).mutex);
   
    return result;
  }

  for (i=0; i<(int)size; i++) {
    p[i] = getch();
    if (p[i] < 0) 
      return i;
  }

  return (int)size;
  #endif

  return 0;
}

off_t
sys_lseek(int fd, off_t offset, int whence, int *errp) {
  #if OPT_SYSCALLS
  if (fd < 0 || fd >= OPEN_MAX || curproc->fileTable[fd] == NULL) { *errp = EBADF; return -1; }
  
  struct openfile *of = curproc->fileTable[fd];

  switch (whence)
  {
    case SEEK_SET:
      of->offset = offset;
      break;

    case SEEK_CUR:
      of->offset += offset;
      break;

    case SEEK_END:
      of->offset = of->size + offset;
      break;
    
    default:
      *errp = EINVAL;
      return -1;
  }
  
  if (of->offset > of->size) 
    of->offset = of->size;

  return of->offset;

  #endif

  return -1;
}

int
sys_dup2(int oldfd, int newfd, int *errp) {
  #if OPT_SYSCALLS
  if (newfd < STDERR_FILENO || newfd >= OPEN_MAX) { *errp = EBADF; return -1; }
  if (oldfd < STDERR_FILENO || oldfd >= OPEN_MAX || curproc->fileTable[oldfd]==NULL) { *errp = EBADF; return -1; }
  if (oldfd == newfd) return newfd;

  int result;

  if(curproc->fileTable[newfd] != NULL){
    // close the file for this process
    sys_close(newfd, &result);
  }

  struct openfile *of = curproc->fileTable[oldfd];
  curproc->fileTable[newfd] = of;
  openfileIncrRefCount(of);

  return newfd;

  #endif

  return -1;
}
