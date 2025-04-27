/*
 * sched.h
 */

#ifndef _SCHED_H
#define _SCHED_H

#include <klibc/extern.h>
#include <sys/types.h>

/* linux/sched.h is unusable; put the declarations we need here... */

#define SCHED_OTHER             0
#define SCHED_FIFO              1
#define SCHED_RR                2

struct sched_param {
	int sched_priority;
};

__extern int sched_setscheduler(pid_t, int, const struct sched_param *);
__extern int sched_setaffinity(pid_t, unsigned int, unsigned long *);
__extern int sched_getaffinity(pid_t, unsigned int, unsigned long *);
__extern int sched_yield(void);

/* Raw interface to clone(2); only actually usable for non-VM-cloning */
__extern pid_t __clone(int, void *);

#endif				/* _SCHED_H */
