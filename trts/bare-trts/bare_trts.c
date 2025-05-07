#include "bare_trts.h"


void *memcpy(void *dest, const void *src, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		((char *)dest)[i] = ((char *)src)[i];

	return dest;
}

void *memset(void *dest, int c, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		((char *)dest)[i] = c;

	return dest;
 } 

/*
	Taken from the linux kernel sgx selftests
	https://github.com/torvalds/linux/blob/master/tools/testing/selftests/sgx/test_encl.c

*/
int is_outside_enclave(void *addr, size_t len)
{
	size_t start = (size_t) addr;
	size_t end = start + len - 1;
	size_t enclave_end = get_enclave_base() + get_enclave_size();

	if (start > end)
			return 0;

	return (start > enclave_end) || (end < get_enclave_base());
}

int is_inside_enclave(void *addr, size_t len)
{
	/*Cast to avoid undefined void pointer arithmetics in C */
	size_t start = (size_t) addr;
	size_t end = start + len - 1;
	size_t enclave_end = get_enclave_base() + get_enclave_size();

	if (start > end)
			return 0;

	return (start >= get_enclave_base() && end <= enclave_end);
}

void panic(void)
{
	//ud2 undefined instruction exception
	asm("ud2\n\t");
}

void assert_inside_enclave(void *u_arg, size_t size)
{	
	if(!is_inside_enclave((void *) (u_arg), size))
	{
		panic();
	}
}


