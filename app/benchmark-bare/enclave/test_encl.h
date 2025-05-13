#ifndef TEST_ENCL_H_INC
#define TEST_ENCL_H_INC

#include <stddef.h>
#include <stdint.h>

enum encl_op_type {
	ENCL_OP_ADD,
	ENCL_OP_SUB,
        ENCL_OP_RET,
        ENCL_OP_MAX,
};

struct encl_op_header {
	uint64_t type;
};

struct encl_op_math {
	struct encl_op_header header;
        uint64_t val1;
        uint64_t val2;
        uint64_t *rv_pt;
};

struct encl_op_ret {
        struct encl_op_header header;
};

//static void do_encl_op_add(void *_op);
//static void do_encl_op_sub(void *_op);
//
//
//static int is_inside_enclave(void *addr, size_t len);
//static int is_outside_enclave(void *addr, size_t len);
//
//static inline void panic(void);
//
//static void *memcpy(void *dest, const void *src, size_t n)
//static void *memset(void *dest, int c, size_t n)

#endif
