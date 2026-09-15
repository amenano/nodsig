/* nodsig_hash.c — see nodsig_hash.h. SHA-256 from FIPS 180-4, RIPEMD-160
 * ported line by line from `hashing._ripemd160_pure` (same tables, same
 * two lines, same final mixing), so a reader can hold the two side by
 * side. */
#include "nodsig_hash.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_compress(uint32_t s[8], const uint8_t p[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16
             | (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = s[0]; b = s[1]; c = s[2]; d = s[3];
    e = s[4]; f = s[5]; g = s[6]; h = s[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25))
           + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22))
           + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
    s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

void nodsig_sha256_init(nodsig_sha256_ctx *ctx)
{
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(ctx->state, iv, sizeof iv);
    ctx->length = 0;
    ctx->fill = 0;
}

void nodsig_sha256_update(nodsig_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->length += len;
    if (ctx->fill) {
        size_t take = 64 - ctx->fill;
        if (take > len)
            take = len;
        memcpy(ctx->buf + ctx->fill, data, take);
        ctx->fill += take;
        data += take;
        len -= take;
        if (ctx->fill < 64)
            return;
        sha256_compress(ctx->state, ctx->buf);
        ctx->fill = 0;
    }
    while (len >= 64) {
        sha256_compress(ctx->state, data);
        data += 64;
        len -= 64;
    }
    if (len) {
        memcpy(ctx->buf, data, len);
        ctx->fill = len;
    }
}

void nodsig_sha256_final(nodsig_sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bits = ctx->length * 8;
    size_t r = ctx->fill;
    int j;
    ctx->buf[r++] = 0x80;
    if (r > 56) {
        memset(ctx->buf + r, 0, 64 - r);
        sha256_compress(ctx->state, ctx->buf);
        r = 0;
    }
    memset(ctx->buf + r, 0, 56 - r);
    for (j = 0; j < 8; j++)
        ctx->buf[63 - j] = (uint8_t)(bits >> (8 * j));
    sha256_compress(ctx->state, ctx->buf);
    for (j = 0; j < 8; j++) {
        out[4 * j]     = (uint8_t)(ctx->state[j] >> 24);
        out[4 * j + 1] = (uint8_t)(ctx->state[j] >> 16);
        out[4 * j + 2] = (uint8_t)(ctx->state[j] >> 8);
        out[4 * j + 3] = (uint8_t)(ctx->state[j]);
    }
}

void nodsig_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    nodsig_sha256_ctx ctx;
    nodsig_sha256_init(&ctx);
    nodsig_sha256_update(&ctx, data, len);
    nodsig_sha256_final(&ctx, out);
}

void nodsig_sha256d(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint8_t t[32];
    nodsig_sha256(data, len, t);
    nodsig_sha256(t, 32, out);
}

/* ------------------------------------------------------------------ */
/* RIPEMD-160, the tables of hashing._ripemd160_pure                   */
/* ------------------------------------------------------------------ */

static const uint32_t K1[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
static const uint32_t K2[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};
static const uint8_t R1[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
static const uint8_t R2[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
static const uint8_t S1[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
static const uint8_t S2[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t rmd_f(int j, uint32_t x, uint32_t y, uint32_t z)
{
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

static void rmd_compress(uint32_t h[5], const uint8_t p[64])
{
    uint32_t x[16];
    uint32_t a, b, c, d, e, A, B, C, D, E, t;
    int i, j;
    for (i = 0; i < 16; i++)
        x[i] = (uint32_t)p[4 * i] | (uint32_t)p[4 * i + 1] << 8
             | (uint32_t)p[4 * i + 2] << 16 | (uint32_t)p[4 * i + 3] << 24;
    a = A = h[0]; b = B = h[1]; c = C = h[2]; d = D = h[3]; e = E = h[4];
    for (j = 0; j < 80; j++) {
        /* left line: a, e, d, c, b = e, d, rol(c, 10), b, rol(a + f + x + K, s) + e */
        t = ROL32(a + rmd_f(j, b, c, d) + x[R1[j]] + K1[j / 16], S1[j]) + e;
        a = e; e = d; d = ROL32(c, 10); c = b; b = t;
        /* right line: the mirrored schedule */
        t = ROL32(A + rmd_f(79 - j, B, C, D) + x[R2[j]] + K2[j / 16], S2[j]) + E;
        A = E; E = D; D = ROL32(C, 10); C = B; B = t;
    }
    t = h[1] + c + D;
    h[1] = h[2] + d + E;
    h[2] = h[3] + e + A;
    h[3] = h[4] + a + B;
    h[4] = h[0] + b + C;
    h[0] = t;
}

void nodsig_ripemd160(const uint8_t *data, size_t len, uint8_t out[20])
{
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t blk[128];
    uint64_t bits = (uint64_t)len * 8;
    size_t i = 0, r, pad;
    int j;
    for (; i + 64 <= len; i += 64)
        rmd_compress(h, data + i);
    r = len - i;
    memcpy(blk, data + i, r);
    blk[r++] = 0x80;
    pad = (r <= 56) ? 64 : 128;
    memset(blk + r, 0, pad - r);
    for (j = 0; j < 8; j++)
        blk[pad - 8 + j] = (uint8_t)(bits >> (8 * j));   /* little-endian */
    rmd_compress(h, blk);
    if (pad == 128)
        rmd_compress(h, blk + 64);
    for (j = 0; j < 5; j++) {
        out[4 * j]     = (uint8_t)(h[j]);
        out[4 * j + 1] = (uint8_t)(h[j] >> 8);
        out[4 * j + 2] = (uint8_t)(h[j] >> 16);
        out[4 * j + 3] = (uint8_t)(h[j] >> 24);
    }
}

void nodsig_hash160(const uint8_t *data, size_t len, uint8_t out[20])
{
    uint8_t t[32];
    nodsig_sha256(data, len, t);
    nodsig_ripemd160(t, 32, out);
}
