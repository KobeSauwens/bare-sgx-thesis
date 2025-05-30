#ifndef TEST_ENCL_H_INC
#define TEST_ENCL_H_INC

#include <stddef.h>
#include <stdint.h>

#define DIGEST_LEN      32
#define KEY_LEN_AEAD    32
#define KEY_LEN_HMAC    16
#define MAC_LEN         16
#define KEY_LEN_AES     16
#define NONCE_LEN       12


enum encl_op_type {
	ENCL_OP_ADD,
	ENCL_OP_SUB,
        ENCL_OP_HMAC,
        ENCL_OP_AEAD_ENC,
        ENCL_OP_AEAD_DEC,
        ENCL_OP_AES_GCM_128_ENC,
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

// According to HACL* API https://hacl-star.github.io/HaclAEAD.html
struct encl_op_AEAD {
        struct encl_op_header header_AEAD;
        uint8_t *n;             // 12-bit nonce
        uint32_t aadlen;        // Associated data length
        uint8_t *aad;           // Associated data
        uint32_t mlen;          // Message length
        uint8_t *m;             // Message
        uint8_t *cipher;        // Ciphertext
        uint8_t *mac;           // Mac
};
// static void do_encl_op_add(void *_op);
// static void do_encl_op_sub(void *_op);


// static int is_inside_enclave(void *addr, size_t len);
// static int is_outside_enclave(void *addr, size_t len);

// static inline void panic(void);


#endif
