#ifndef BARE_TRTS_H_INC
#define BARE_TRTS_H_INC

#include <stddef.h>
#include <stdint.h>


/* Based on the patches by Jo Van Bulck of the test-enclave in the Linux Kernel 
	https://lkml.org/lkml/2023/7/19/798
*/
#define SAFE_COPY_STRUCT(u_arg, t_cp)	do { 			\
		if (!sgx_is_outside_enclave(u_arg, sizeof(t_cp)))	\
		{												\
			panic();									\
		}												\
		memcpy(t_cp,u_arg,sizeof(*t_cp));				\
	} while(0)											\

#define sgx_lfence() asm("lfence\n\t");


/* Based on the patches by Jo Van Bulck of the test-enclave in the Linux Kernel 
	https://lkml.org/lkml/2023/7/19/798
*/
uint64_t get_enclave_base(void);
uint64_t get_enclave_size(void);



int sgx_is_outside_enclave(void *addr, size_t len);
int sgx_is_within_enclave(void *addr, size_t len);

void panic(void);

void *memcpy(void *dest, const void *src, size_t n);
void *memcpy_s(void *dest, size_t n, const void *src, size_t l);
void *memcpy_verw_s(void *dest, size_t n, const void *src, size_t l);

void *memset(void *dest, int c, size_t n);


void *malloc( size_t xWantedSize );
void free( void * pv );

void assert_inside_enclave(void *u_arg, size_t size);

#endif
