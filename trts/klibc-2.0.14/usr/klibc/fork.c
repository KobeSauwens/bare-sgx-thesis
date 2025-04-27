/*
 * fork.c
 *
 * This is normally just a syscall stub, but new architectures only
 * implement clone().
 */

#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <klibc/sysconfig.h>

#ifndef __NR_fork

pid_t fork(void)
{
	return __clone(SIGCHLD, 0);
}

#endif
