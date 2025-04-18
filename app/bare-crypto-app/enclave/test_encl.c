// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include "test_encl.h"
#include "hacl-c/Hacl_HMAC_SHA2_256.h"

/* Based on the patches by Jo Van Bulck of the test-enclave in the Linux Kernel 
	https://lkml.org/lkml/2023/7/19/798
*/

uint64_t get_enclave_base(void);
uint64_t get_enclave_size(void);

/*
	Taken from the linux kernel sgx selftests
	https://github.com/torvalds/linux/blob/master/tools/testing/selftests/sgx/test_encl.c

*/

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

static int is_outside_enclave(void *addr, size_t len)
{
	size_t start = (size_t) addr;
	size_t end = start + len - 1;
	size_t enclave_end = get_enclave_base() + get_enclave_size();

	if (start > end)
			return 0;

	return (start > enclave_end) || (end < get_enclave_base());
}

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



static inline void panic(void)
{
	//ud2 undefined instruction exception
	asm("ud2\n\t");
}

static void do_encl_op_add(void *_op)
{
	struct encl_op_math op;

	SAFE_COPY_STRUCT(_op,&op);
        /* TODO *insecure* ptr dereference: needs a check */
	*op.rv_pt = op.val1 + op.val2;
}

static void do_encl_op_sub(void *_op)
{
	struct encl_op_math op;

	SAFE_COPY_STRUCT(_op,&op);
        /* TODO *insecure* ptr dereference: needs a check */
	*op.rv_pt = op.val1 - op.val2;
}

static void do_encl_op_hmac(void *_op)
{
	struct encl_op_hmac *op = _op;

    uint8_t key[KEY_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    hmac(op->digest, key, KEY_LEN, op->message, 0);//(*op).message_len);
}


static int is_inside_enclave(void *addr, size_t len)
{
	/*Cast to avoid undefined void pointer arithmetics in C */
	size_t start = (size_t) addr;
	size_t end = start + len - 1;
	size_t enclave_end = get_enclave_base() + get_enclave_size();

	if (start > end)
			return 0;

	return (start >= get_enclave_base() && end <= enclave_end);
}



static inline void assert_inside_enclave(void *u_arg, size_t size)
{	
	if(!is_inside_enclave((void *) (u_arg), size))
	{
		panic();
	}
}


/*
 * Symbol placed at the start of the enclave image by the linker script.
 * Declare this extern symbol with visibility "hidden" to ensure the compiler
 * does not access it through the GOT and generates position-independent
 * addressing as __encl_base(%rip), so we can get the actual enclave base
 * during runtime.
 */
extern const uint8_t __attribute__((visibility("hidden"))) __enclave_base;

typedef void (*encl_op_t)(void *);

/* NOTE: need to declare this volatile to preven the compiler from inlining the
 * accesses in encl_body and breaking the manual relocation.. */
volatile encl_op_t encl_op_array[ENCL_OP_MAX] = {
	do_encl_op_add,
	do_encl_op_sub,
	do_encl_op_hmac,
};


void encl_body(void *rdi, void *rsi)
{
	struct encl_op_header *header = (struct encl_op_header *)rdi;
	encl_op_t op;

	/*TODO *insecure* ptr dereference: needs a check */
	
	// if(!is_outside_enclave(header,sizeof(encl_op_header)))
	// {
	// 	panic();
	// }
	if (header->type >= ENCL_OP_MAX)
		return;

	/*
	 * The enclave base address needs to be added, as this call site
	 * *cannot be* made rip-relative by the compiler, or fixed up by
	 * any other possible means.
	 */
	op = ((uint64_t)&__enclave_base) + encl_op_array[header->type];
	(*op)(header);
}

// void encl_body(void *rdi, void *rsi)
// {
// 	size_t *number = (size_t *) rdi;
// 	(*number)++;
// }