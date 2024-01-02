#include <bits/syscall.h>

#include <mlibc/fsfd_target.hpp>
#include <abi-bits/socklen_t.h>
#include <abi-bits/fcntl.h>

#include <poll.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>

namespace mlibc
{
	void sys_libc_log(const char *message)
	{
		/* not implemented */
	}

	void sys_libc_panic()
	{
		sys_libc_log("libc panic!");
		__builtin_trap();
		for(;;);
	}

	int sys_futex_wait(int *pointer, int expected, const struct timespec *time)
	{
		sys_libc_log("mlibc warning: sys_futex_wait: not implemented");
		return 0;
	}

	int sys_futex_wake(int *pointer)
	{
		sys_libc_log("mlibc warning: sys_futex_wake: not implemented");
		return 0;
	}

	void sys_exit(int status)
	{
		syscall(SYS_exit, status);
	}

	void sys_thread_exit()
	{
		sys_libc_log("mlibc warning: sys_thread_exit: not implemented");
	}

	int sys_clock_get(int clock, time_t *secs, long *nanos)
	{
		sys_libc_log("mlibc warning: sys_clock_get: not implemented");
		return 0;
	}

	int sys_open(const char *pathname, int flags, mode_t mode, int *fd)
	{
		long ret = syscall(SYS_openat, AT_FDCWD, pathname, flags, mode);
		if (ret < 0) {
			return -ret;
		}
		*fd = ret;
		return 0;
	}

	int sys_flock(int fd, int options)
	{
		sys_libc_log("mlibc warning: sys_flock: not implemented");
		return 0;
	}

	int sys_open_dir(const char *path, int *handle)
	{
		sys_libc_log("mlibc warning: sys_open_dir: not implemented");
		return 0;
	}

	int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read)
	{
		sys_libc_log("mlibc warning: sys_read_entries: not implemented");
		return 0;
	}

	int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read)
	{
		long ret = syscall(SYS_read, fd, buf, count);
		if (ret < 0) {
			*bytes_read = 0;
			return -ret;
		}
		*bytes_read = ret;
		return 0;
	}

	int sys_readv(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_read)
	{
		sys_libc_log("mlibc warning: sys_readv: not implemented");
		return 0;
	}

	int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written)
	{
		long ret = syscall(SYS_write, fd, buf, count);
		if (ret < 0) {
			*bytes_written = 0;
			return -ret;
		}
		*bytes_written = ret;
		return 0;
	}

	int sys_pread(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read)
	{
		sys_libc_log("mlibc warning: sys_pread: not implemented");
		return 0;
	}

	int sys_pwrite(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_read)
	{
		sys_libc_log("mlibc warning: sys_pwrite: not implemented");
		return 0;
	}

	int sys_seek(int fd, off_t offset, int whence, off_t *new_offset)
	{
		long ret = syscall(SYS_lseek, fd, offset, whence);
		if (ret < 0) {
			return -ret;
		}
		*new_offset = ret;
		return 0;
	}

	int sys_close(int fd)
	{
		return -syscall(SYS_close, fd);
	}

	int sys_access(const char *path, int mode)
	{
		return -syscall(SYS_faccessat, AT_FDCWD, path, mode, 0);
	}

	int sys_faccessat(int dirfd, const char *pathname, int mode, int flags)
	{
		return -syscall(SYS_faccessat, dirfd, pathname, mode, flags);
	}

	int sys_dup(int fd, int flags, int *newfd)
	{
		long ret = syscall(SYS_dup, fd);
		if (ret < 0) {
			return -ret;
		}
		*newfd = ret;
		return 0;
	}

	int sys_dup2(int fd, int flags, int newfd)
	{
		long ret = syscall(SYS_dup2, fd, newfd);
		if (ret < 0) {
			return -ret;
		}
		return 0;
	}

	int sys_isatty(int fd)
	{
		sys_libc_log("mlibc warning: sys_isatty: not implemented");
		return 0;
	}

	int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags,
			struct stat *statbuf)
	{
		if (fsfdt == fsfd_target::fd) {
			flags |= AT_EMPTY_PATH;
		}
		return -syscall(SYS_fstatat, fd, path, statbuf, flags);
	}

	int sys_statvfs(const char *path, struct statvfs *out)
	{
		sys_libc_log("mlibc warning: sys_statvfs: not implemented");
		return 0;
	}

	int sys_fstatvfs(int fd, struct statvfs *out)
	{
		sys_libc_log("mlibc warning: sys_fstatvfs: not implemented");
		return 0;
	}

	ssize_t sys_readlink(const char *path, char *buffer, size_t max_size,
			ssize_t *length)
	{
		long ret = syscall(SYS_readlink, path, buffer, max_size);
		if (ret < 0) {
			return -ret;
		}
		*length = ret;
		return 0;
	}

	int sys_rmdir(const char *path)
	{
		return -syscall(SYS_unlinkat, AT_FDCWD, path, AT_REMOVEDIR);
	}

	int sys_ftruncate(int fd, size_t size)
	{
		return -syscall(SYS_truncate, fd, NULL, size, AT_EMPTY_PATH);
	}

	int sys_fallocate(int fd, off_t offset, size_t size)
	{
		sys_libc_log("mlibc warning: sys_fallocate: not implemented");
		return 0;
	}

	int sys_unlinkat(int fd, const char *path, int flags)
	{
		return -syscall(SYS_unlinkat, fd, path, flags);
	}

	int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd)
	{
		long ret = syscall(SYS_openat, dirfd, path, flags, mode);
		if (ret < 0) {
			return -ret;
		}
		*fd = ret;
		return 0;
	}

	int sys_socket(int family, int type, int protocol, int *fd)
	{
		sys_libc_log("mlibc warning: sys_socket: not implemented");
		return 0;
	}

	int sys_msg_send(int fd, const struct msghdr *hdr, int flags, ssize_t *length)
	{
		sys_libc_log("mlibc warning: sys_msg_send: not implemented");
		return 0;
	}

	int sys_msg_recv(int fd, struct msghdr *hdr, int flags, ssize_t *length)
	{
		sys_libc_log("mlibc warning: sys_msg_recv: not implemented");
		return 0;
	}

	int sys_listen(int fd, int backlog)
	{
		sys_libc_log("mlibc warning: sys_listen: not implemented");
		return 0;
	}

	gid_t sys_getgid()
	{
		return syscall(SYS_getgid);
	}

	gid_t sys_getegid()
	{
		return syscall(SYS_getegid);
	}

	uid_t sys_getuid()
	{
		return syscall(SYS_getuid);
	}

	uid_t sys_geteuid()
	{
		return syscall(SYS_geteuid);
	}

	pid_t sys_getpid()
	{
		return syscall(SYS_getpid);
	}

	pid_t sys_gettid()
	{
		sys_libc_log("mlibc warning: sys_gettid: not implemented");
		return 0;
	}

	pid_t sys_getppid()
	{
		return syscall(SYS_getppid);
	}

	pid_t sys_getpgid(pid_t pid, pid_t *pgid)
	{
		sys_libc_log("mlibc warning: sys_getpgid: not implemented");
		return 0;
	}

	pid_t sys_getsid(pid_t pid, pid_t *sid)
	{
		sys_libc_log("mlibc warning: sys_getsid: not implemented");
		return 0;
	}

	int sys_setpgid(pid_t pid, pid_t pgid)
	{
		sys_libc_log("mlibc warning: sys_pgid: not implemented");
		return 0;
	}

	int sys_setuid(uid_t uid)
	{
		sys_libc_log("mlibc warning: sys_setuid: not implemented");
		return 0;
	}

	int sys_seteuid(uid_t euid)
	{
		sys_libc_log("mlibc warning: sys_seteuid: not implemented");
		return 0;
	}

	int sys_setgid(gid_t gid)
	{
		sys_libc_log("mlibc warning: sys_setgid: not implemented");
		return 0;
	}

	int sys_setegid(gid_t egid)
	{
		sys_libc_log("mlibc warning: sys_setegid: not implemented");
		return 0;
	}

	int sys_getgroups(size_t size, const gid_t *list, int *ret)
	{
		sys_libc_log("mlibc warning: sys_getgroups: not implemented");
		return 0;
	}

	void sys_yield()
	{
		sys_libc_log("mlibc warning: sys_yield: not implemented");
	}

	int sys_sleep(time_t *secs, long *nanos)
	{
		sys_libc_log("mlibc warning: sys_sleep: not implemented");
		return 0;
	}

	int sys_fork(pid_t *child)
	{
		long pid = syscall(SYS_fork);
		if (pid < 0) {
			errno = pid;
			return -1;
		}
		*child = pid;
		return 0;
	}

	int sys_clone(void *tcb, pid_t *pid_out, void *stack)
	{
		sys_libc_log("mlibc warning: sys_clone: not implemented");
		return 0;
	}

	int sys_prepare_stack(void **stack, void *entry, void *user_arg, void* tcb, size_t *stack_size, size_t *guard_size)
	{
		sys_libc_log("mlibc warning: sys_prepare_stack: not implemented");
		return 0;
	}

	int sys_execve(const char *path, char *const argv[], char *const envp[])
	{
		return -syscall(SYS_execve, path, argv, envp);
	}

	int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set,
	   fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events)
	{
		sys_libc_log("mlibc warning: sys_pselect: not implemented");
		return 0;
	}

	int sys_getrusage(int scope, struct rusage *usage)
	{
		sys_libc_log("mlibc warning: sys_getrusage: not implemented");
		return 0;
	}

	int sys_getrlimit(int resource, struct rlimit *limit)
	{
		sys_libc_log("mlibc warning: sys_getrlimit: not implemented");
		return 0;

	}

	int sys_setrlimit(int resource, const struct rlimit *limit)
	{
		sys_libc_log("mlibc warning: sys_setrlimit: not implemented");
		return 0;
	}

	int sys_getpriority(int which, id_t who, int *value)
	{
		sys_libc_log("mlibc warning: sys_getpriority: not implemented");
		return 0;
	}

	int sys_setpriority(int which, id_t who, int prio)
	{
		sys_libc_log("mlibc warning: sys_setpriority: not implemented");
		return 0;
	}

	int sys_getschedparam(void *tcb, int *policy, struct sched_param *param)
	{
		sys_libc_log("mlibc warning: sys_getschedparam: not implemented");
		return 0;
	}

	int sys_setschedparam(void *tcb, int policy, const struct sched_param *param)
	{
		sys_libc_log("mlibc warning: sys_setschedparam: not implemented");
		return 0;
	}

	int sys_get_min_priority(int policy, int *out)
	{
		sys_libc_log("mlibc warning: sys_get_min_priority: not implemented");
		return 0;
	}

	int sys_getcwd(char *buffer, size_t size)
	{
		return -syscall(SYS_getcwd, buffer, size);
	}

	int sys_chdir(const char *path)
	{
		return -syscall(SYS_chdir, 0, path, 0);
	}

	int sys_fchdir(int fd)
	{
		return -syscall(SYS_chdir, fd, NULL, AT_EMPTY_PATH);
	}

	int sys_chroot(const char *path)
	{
		sys_libc_log("mlibc warning: sys_chroot: not implemented");
		return 0;
	}

	int sys_mkdir(const char *path, mode_t mode)
	{
		return -syscall(SYS_mkdirat, AT_FDCWD, path, mode);
	}

	int sys_mkdirat(int dirfd, const char *path, mode_t mode)
	{
		return -syscall(SYS_mkdirat, dirfd, path, mode);
	}

	int sys_link(const char *old_path, const char *new_path)
	{
		return -syscall(SYS_linkat, AT_FDCWD, old_path, AT_FDCWD, new_path, 0);
	}

	int sys_linkat(int olddirfd, const char *old_path, int newdirfd,
			const char *new_path, int flags)
	{
		return -syscall(SYS_linkat, olddirfd, old_path, newdirfd, new_path, flags);
	}

	int sys_symlink(const char *target_path, const char *link_path)
	{
		return -syscall(SYS_symlinkat, target_path, AT_FDCWD, link_path);
	}

	int sys_symlinkat(const char *target_path, int dirfd, const char *link_path)
	{
		return -syscall(SYS_symlinkat, target_path, dirfd, link_path);
	}

	int sys_rename(const char *path, const char *new_path)
	{
		return -syscall(SYS_renameat2, AT_FDCWD, path, AT_FDCWD, new_path, 0);
	}

	int sys_renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path)
	{
		return -syscall(SYS_renameat2, olddirfd, old_path, newdirfd, new_path, 0);
	}

	int sys_fcntl(int fd, int request, va_list args, int *result)
	{
		long ret = syscall(SYS_fcntl, fd, request, va_arg(args, int));
		if (ret < 0) {
			return -ret;
		}
		*result = ret;
		return 0;
	}

	int sys_ttyname(int fd, char *buf, size_t size)
	{
		sys_libc_log("mlibc warning: sys_ttyname: not implemented");
		return 0;
	}

	int sys_fadvise(int fd, off_t offset, off_t length, int advice)
	{
		sys_libc_log("mlibc warning: sys_fadvise: not implemented");
		return 0;
	}

	void sys_sync()
	{
		sys_libc_log("mlibc warning: sys_sync: not implemented");
	}

	int sys_fsync(int fd)
	{
		sys_libc_log("mlibc warning: sys_fsync: not implemented");
		return 0;
	}

	int sys_fdatasync(int fd)
	{
		sys_libc_log("mlibc warning: sys_fdatasync: not implemented");
		return 0;
	}

	int sys_chmod(const char *pathname, mode_t mode)
	{
		return -syscall(SYS_fchmodat, AT_FDCWD, pathname, mode, 0);
	}

	int sys_fchmod(int fd, mode_t mode)
	{
		return -syscall(SYS_fchmodat, fd, NULL, mode, AT_EMPTY_PATH);
	}

	int sys_fchmodat(int fd, const char *pathname, mode_t mode, int flags)
	{
		return -syscall(SYS_fchmodat, fd, pathname, mode, flags);
	}

	int sys_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags)
	{
		sys_libc_log("mlibc warning: sys_utimensat: not implemented");
		return 0;
	}

	int sys_mlock(const void *addr, size_t length)
	{
		sys_libc_log("mlibc warning: sys_mlock: not implemented");
		return 0;
	}

	int sys_munlock(const void *addr, size_t length)
	{
		sys_libc_log("mlibc warning: sys_munlock: not implemented");
		return 0;
	}

	int sys_mlockall(int flags)
	{
		sys_libc_log("mlibc warning: sys_mlockall: not implemented");
		return 0;
	}

	int sys_munlockall(void)
	{
		sys_libc_log("mlibc warning: sys_munlockall: not implemented");
		return 0;
	}

	int sys_mincore(void *addr, size_t length, unsigned char *vec)
	{
		sys_libc_log("mlibc warning: sys_mincore: not implemented");
		return 0;
	}

	int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window)
	{
		sys_libc_log("mlibc warning: sys_vm_map: not implemented");
		return 0;
	}

	int sys_vm_remap(void *pointer, size_t size, size_t new_size, void **window)
	{
		sys_libc_log("mlibc warning: sys_vm_remap: not implemented");
		return 0;
	}

	int sys_vm_protect(void *pointer, size_t size, int prot)
	{
		sys_libc_log("mlibc warning: sys_vm_protect: not implemented");
		return 0;
	}

	int sys_vm_unmap(void* address, size_t size)
	{
		sys_libc_log("mlibc warning: sys_vm_unmap: not implemented");
		return 0;
	}

	int sys_setsid(pid_t *sid)
	{
		sys_libc_log("mlibc warning: sys_setsid: not implemented");
		return 0;
	}

	int sys_tcgetattr(int fd, struct termios *attr)
	{
		sys_libc_log("mlibc warning: sys_tcgetattr: not implemented");
		return 0;
	}

	int sys_tcsetattr(int, int, const struct termios *attr)
	{
		sys_libc_log("mlibc warning: sys_tcsetattr: not implemented");
		return 0;
	}

	int sys_tcflow(int, int)
	{
		sys_libc_log("mlibc warning: sys_tcflow: not implemented");
		return 0;
	}

	int sys_tcflush(int fd, int queue)
	{
		sys_libc_log("mlibc warning: sys_tcflush: not implemented");
		return 0;
	}

	int sys_tcdrain(int)
	{
		sys_libc_log("mlibc warning: sys_tcdrain: not implemented");
		return 0;
	}

	int sys_pipe(int *fds, int flags)
	{
		return -syscall(SYS_pipe2, fds, flags);
	}

	int sys_socketpair(int domain, int type_and_flags, int proto, int *fds)
	{
		sys_libc_log("mlibc warning: sys_socketpair: not implemented");
		return 0;
	}

	int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events)
	{
		sys_libc_log("mlibc warning: sys_poll: not implemented");
		return 0;
	}

	int sys_ioctl(int fd, unsigned long request, void *arg, int *result)
	{
		sys_libc_log("mlibc warning: sys_ioctl: not implemented");
		return 0;
	}

	int sys_getsockopt(int fd, int layer, int number,
			void *__restrict buffer, socklen_t *__restrict size)
	{
		sys_libc_log("mlibc warning: sys_getsockopt: not implemented");
		return 0;
	}

	int sys_setsockopt(int fd, int layer, int number,
			const void *buffer, socklen_t size)
	{
		sys_libc_log("mlibc warning: sys_setsockopt: not implemented");
		return 0;
	}

	int sys_sigprocmask(int how, const sigset_t *__restrict set,
			sigset_t *__restrict retrieve)
	{
		sys_libc_log("mlibc warning: sys_sigprocmask: not implemented");
		return 0;
	}

	int sys_sigaction(int, const struct sigaction *__restrict,
			struct sigaction *__restrict)
	{
		sys_libc_log("mlibc warning: sys_sigaction: not implemented");
		return 0;
	}

	int sys_sigtimedwait(const sigset_t *__restrict set, siginfo_t *__restrict info,
			const struct timespec *__restrict timeout, int *out_signal)
	{
		sys_libc_log("mlibc warning: sys_sigtimedwait: not implemented");
		return 0;
	}

	int sys_kill(int pid, int sig)
	{
		sys_libc_log("mlibc warning: sys_kill: not implemented");
		return 0;
	}

	int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length)
	{
		sys_libc_log("mlibc warning: sys_accept: not implemented");
		return 0;
	}

	int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length)
	{
		sys_libc_log("mlibc warning: sys_bind: not implemented");
		return 0;
	}

	int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length)
	{
		sys_libc_log("mlibc warning: sys_connect: not implemented");
		return 0;
	}

	int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
			socklen_t *actual_length)
	{
		sys_libc_log("mlibc warning: sys_sockname: not implemented");
		return 0;
	}

	int sys_peername(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
			socklen_t *actual_length)
	{
		sys_libc_log("mlibc warning: sys_peername: not implemented");
		return 0;
	}

	int sys_gethostname(char *buffer, size_t bufsize)
	{
		sys_libc_log("mlibc warning: sys_gethostname: not implemented");
		return 0;
	}

	int sys_sethostname(const char *buffer, size_t bufsize)
	{
		sys_libc_log("mlibc warning: sys_sethostname: not implemented");
		return 0;
	}

	int sys_mkfifoat(int dirfd, const char *path, int mode)
	{
		return -syscall(SYS_mkfifoat, dirfd, path, mode);
	}

	int sys_getentropy(void *buffer, size_t length)
	{
		sys_libc_log("mlibc warning: sys_getentropy: not implemented");
		return 0;
	}

	int sys_mknodat(int dirfd, const char *path, int mode, int dev)
	{
		return -syscall(SYS_mknodat, dirfd, path, mode, dev);
	}

	int sys_umask(mode_t mode, mode_t *old)
	{
		long ret = syscall(SYS_umask, mode);
		if (ret < 0) {
			return -ret;
		}
		*old = ret;
		return 0;
	}

	int sys_before_cancellable_syscall(ucontext_t *uctx)
	{
		sys_libc_log("mlibc warning: sys_before_cancellable_syscall: "
				"not implemented");
		return 0;
	}

	int sys_tgkill(int tgid, int tid, int sig)
	{
		sys_libc_log("mlibc warning: sys_tgkill: not implemented");
		return 0;
	}

	int sys_fchownat(int dirfd, const char *pathname, uid_t owner,
			gid_t group, int flags)
	{
		return -syscall(SYS_fchownat, dirfd, pathname, owner, group, flags);
	}

	int sys_sigaltstack(const stack_t *ss, stack_t *oss)
	{
		sys_libc_log("mlibc warning: sys_sigaltstack: not implemented");
		return 0;
	}

	int sys_sigsuspend(const sigset_t *set)
	{
		sys_libc_log("mlibc warning: sys_sigsuspend: not implemented");
		return 0;
	}

	int sys_setgroups(size_t size, const gid_t *list)
	{
		sys_libc_log("mlibc warning: sys_setgroups: not implemented");
		return 0;
	}

	int sys_statfs(const char *path, struct statfs *buf)
	{
		sys_libc_log("mlibc warning: sys_statfs: not implemented");
		return 0;
	}

	int sys_fstatfs(int fd, struct statfs *buf)
	{
		sys_libc_log("mlibc warning: sys_fstatfs: not implemented");
		return 0;
	}

	int sys_memfd_create(const char *name, int flags, int *fd)
	{
		sys_libc_log("mlibc warning: sys_memfd_create: not implemented");
		return 0;
	}

	int sys_madvise(void *addr, size_t length, int advice)
	{
		sys_libc_log("mlibc warning: sys_madvise: not implemented");
		return 0;
	}

	int sys_msync(void *addr, size_t length, int flags)
	{
		sys_libc_log("mlibc warning: sys_msync: not implemented");
		return 0;
	}

	int sys_getitimer(int which, struct itimerval *curr_value)
	{
		sys_libc_log("mlibc warning: sys_getitimer: not implemented");
		return 0;
	}

	int sys_setitimer(int which, const struct itimerval *new_value,
			struct itimerval *old_value)
	{
		sys_libc_log("mlibc warning: sys_setitimer: not implemented");
		return 0;
	}

	int sys_timer_create(clockid_t clk, struct sigevent *__restrict evp,
			timer_t *__restrict res)
	{
		sys_libc_log("mlibc warning: sys_timer_create: not implemented");
		return 0;
	}

	int sys_timer_settime(timer_t t, int flags,
			const struct itimerspec *__restrict val,
			struct itimerspec *__restrict old)
	{
		sys_libc_log("mlibc warning: sys_timer_settime: not implemented");
		return 0;
	}

	int sys_timer_delete(timer_t t)
	{
		sys_libc_log("mlibc warning: sys_timer_delete: not implemented");
		return 0;
	}

	int sys_times(struct tms *tms, clock_t *out)
	{
		sys_libc_log("mlibc warning: sys_times: not implemented");
		return 0;
	}

	int sys_uname(struct utsname *buf)
	{
		return syscall(SYS_uname, buf);
	}

	int sys_pause()
	{
		sys_libc_log("mlibc warning: sys_pause: not implemented");
		return 0;
	}

	int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
	{
		sys_libc_log("mlibc warning: sys_setresuid: not implemented");
		return 0;
	}

	int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
	{
		sys_libc_log("mlibc warning: sys_setresgid: not implemented");
		return 0;
	}

	int sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
	{
		sys_libc_log("mlibc warning: sys_getresuid: not implemented");
		return 0;
	}

	int sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
	{
		sys_libc_log("mlibc warning: sys_getresgid: not implemented");
		return 0;
	}

	int sys_setreuid(uid_t ruid, uid_t euid)
	{
		sys_libc_log("mlibc warning: sys_setreuid: not implemented");
		return 0;
	}

	int sys_setregid(gid_t rgid, gid_t egid)
	{
		sys_libc_log("mlibc warning: sys_setregid: not implemented");
		return 0;
	}

	int sys_if_indextoname(unsigned int index, char *name)
	{
		sys_libc_log("mlibc warning: sys_if_indextoname: not implemented");
		return 0;
	}

	int sys_if_nametoindex(const char *name, unsigned int *ret)
	{
		sys_libc_log("mlibc warning: sys_if_nametoindex: not implemented");
		return 0;
	}

	int sys_ptsname(int fd, char *buffer, size_t length)
	{
		sys_libc_log("mlibc warning: sys_ptsname: not implemented");
		return 0;
	}

	int sys_unlockpt(int fd)
	{
		sys_libc_log("mlibc warning: sys_unlockpt: not implemented");
		return 0;
	}

	int sys_thread_setname(void *tcb, const char *name)
	{
		sys_libc_log("mlibc warning: sys_thread_setname: not implemented");
		return 0;
	}

	int sys_thread_getname(void *tcb, char *name, size_t size)
	{
		sys_libc_log("mlibc warning: sys_thread_getname: not implemented");
		return 0;
	}

	int sys_clock_getres(int clock, time_t *secs, long *nanos)
	{
		sys_libc_log("mlibc warning: sys_clock_getres: not implemented");
		return 0;
	}

	int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru,
			pid_t *ret_pid)
	{
		long ret = syscall(SYS_wait4, pid, status, flags, ru);
		if (ret < 0) {
			return -ret;
		}
		*ret_pid = ret;
		return 0;
	}

	int sys_brk(void **out)
	{
		sys_libc_log("mlibc warning: sys_brk: not implemented");
		return 0;
	}

	int sys_personality(unsigned long persona, int *out)
	{
		sys_libc_log("mlibc warning: sys_personality: not implemented");
		return 0;
	}

	int sys_tcb_set(void* pointer)
	{
		sys_libc_log("mlibc warning: sys_tcb_set: not implemented");
		return 0;
	}

	int sys_futex_tid()
	{
		sys_libc_log("mlibc warning: sys_futex_tid: not implemented");
		return 0;
	}

	int sys_anon_allocate(size_t size, void **pointer)
	{
		sys_libc_log("mlibc warning: sys_anon_allocate: not implemented");
		return 0;
	}

	int sys_anon_free(void *pointer, size_t size)
	{
		sys_libc_log("mlibc warning: sys_anon_free: not implemented");
		return 0;
	}

	int sys_vm_readahead(void *pointer, size_t size)
	{
		sys_libc_log("mlibc warning: sys_vm_readahead: not implemented");
		return 0;
	}
}

