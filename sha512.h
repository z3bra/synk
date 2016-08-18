#include <stddef.h>
#include <stdint.h>

typedef struct sha512_state {
    uint64_t  length, state[8];
    unsigned long curlen;
    unsigned char buf[128];
} sha512_state;


int sha512_init(sha512_state * md);
int sha512_process(sha512_state * md, const unsigned char *in, unsigned long inlen);
int sha512_done(sha512_state * md, unsigned char *hash);
