#ifndef BARE_TRTS_H_INC
#define BARE_TRTS_H_INC

#include <stddef.h>
#include <stdint.h>

/* Based on the patches by Jo Van Bulck of the test-enclave in the Linux Kernel 
	https://lkml.org/lkml/2023/7/19/798
*/
uint64_t get_enclave_base(void);
uint64_t get_enclave_size(void);

/* Based on the patches by Jo Van Bulck of the test-enclave in the Linux Kernel 
	https://lkml.org/lkml/2023/7/19/798
*/
#define SAFE_COPY_STRUCT(u_arg, t_cp)	do { 			\
		if (!is_outside_enclave(u_arg, sizeof(t_cp)))	\
		{												\
			panic();									\
		}												\
		memcpy(t_cp,u_arg,sizeof(*t_cp));				\
	} while(0)											\


int is_inside_enclave(void *addr, size_t len);
int is_outside_enclave(void *addr, size_t len);

void panic(void);

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *dest, int c, size_t n);

void assert_inside_enclave(void *u_arg, size_t size);

#endif
