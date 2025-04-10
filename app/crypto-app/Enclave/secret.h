#ifndef SECRET_H_INC
#define SECRET_H_INC

#define SECRET_LEN  4
#define SECRET_PIN  "1234"
#define SECRET_KEY 0xdeadbeef
#define SECRET_KEY_SIZE 4


#ifndef le64toh
#define le64toh(x) (x)  // No conversion needed on little-endian systems
#endif

#ifndef htole64
#define htole64(x) (x)  // No conversion needed
#endif

#ifndef be64toh
#define be64toh(x) __builtin_bswap64(x)  // Swap bytes for big-endian
#endif

#ifndef htobe64
#define htobe64(x) __builtin_bswap64(x)  // Swap bytes for big-endian
#endif

#endif
