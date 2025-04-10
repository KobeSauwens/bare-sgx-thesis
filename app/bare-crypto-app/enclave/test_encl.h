#ifndef TEST_ENCL_H_INC
#define TEST_ENCL_H_INC

#include <stddef.h>
#include <stdint.h>

#define DIGEST_LEN 32
#define KEY_LEN 16

enum encl_op_type {
	ENCL_OP_ADD,
	ENCL_OP_SUB,
        ENCL_OP_HMAC,
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

struct encl_op_hmac {
        struct encl_op_header header_hmac;
        uint32_t message_len;
        uint8_t *message;
        uint8_t *digest; 
};

// static void do_encl_op_add(void *_op);
// static void do_encl_op_sub(void *_op);


// static int is_inside_enclave(void *addr, size_t len);
// static int is_outside_enclave(void *addr, size_t len);

// static inline void panic(void);

// static void *memcpy(void *dest, const void *src, size_t n);
// static void *memset(void *dest, int c, size_t n);

#endif
