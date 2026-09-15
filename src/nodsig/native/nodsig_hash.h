/* nodsig_hash.h — the hash primitives of the native kernel: SHA-256 (one
 * shot and incremental), SHA-256 twice, RIPEMD-160, and hash160 =
 * RIPEMD-160(SHA-256(x)). Plain C99, no dependency: the same three
 * functions `nodsig/hashing.py` builds everything on, so the kernel and the
 * reference agree byte for byte on every digest (tests/fixtures/hashing).
 *
 * The C here is the reference kernel's accelerator, never its truth: what a
 * digest must be is stated in Python and in the vectors; this only has to
 * match. Measured on the development machine (no SHA-NI) a portable SHA-256
 * costs within 10% of OpenSSL's, which is why the kernel carries its own and
 * needs no libcrypto at build time.
 */
#ifndef NODSIG_HASH_H
#define NODSIG_HASH_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t length;        /* bytes fed so far */
    uint8_t  buf[64];       /* the block being filled */
    size_t   fill;          /* bytes in buf */
} nodsig_sha256_ctx;

void nodsig_sha256_init(nodsig_sha256_ctx *ctx);
void nodsig_sha256_update(nodsig_sha256_ctx *ctx, const uint8_t *data, size_t len);
void nodsig_sha256_final(nodsig_sha256_ctx *ctx, uint8_t out[32]);

void nodsig_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void nodsig_sha256d(const uint8_t *data, size_t len, uint8_t out[32]);
void nodsig_ripemd160(const uint8_t *data, size_t len, uint8_t out[20]);
void nodsig_hash160(const uint8_t *data, size_t len, uint8_t out[20]);

#endif
