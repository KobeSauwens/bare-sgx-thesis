/*
 * inotify_init.c
 *
 * Some architectures need to wrap the system call
 */

#include <unistd.h>
#include <sys/inotify.h>
#include <sys/syscall.h>

#ifndef __NR_inotify_init

int inotify_init(void)
{
	return inotify_init1(0);
}

#endif
