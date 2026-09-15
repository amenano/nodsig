/* nodsig_scan.c — see nodsig_scan.h. The walk is blockparse.parse_block
 * and parse_tx, ported with the same refusals in the same places, with
 * reveal_archive.block_records folded into it: an output is extracted
 * as soon as its scriptPubKey is in view, an input once its witness is
 * (the witness of input i is serialized after every output). */
#include "nodsig_scan.h"
#include "nodsig_extract.h"
#include "nodsig_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nodsig_digest_len(int cat)
{
    return (cat == NODSIG_SCRIPTS32 || cat == NODSIG_PROGRAMS32) ? 32 : 20;
}

/* One input, as the parser meets it (its witness comes later). */
typedef struct {
    const uint8_t *prev_txid;
    uint32_t prev_vout;
    const uint8_t *script_sig;
    size_t sig_len;
    size_t wit_start;     /* index into scan->witness of its first item */
    size_t wit_count;
} input_t;

struct nodsig_scan {
    nodsig_extract x;
    input_t *inputs;      /* the inputs of the transaction at hand */
    size_t n_inputs, cap_inputs;
    nodsig_spans witness; /* every witness item of the transaction at hand */
    nodsig_buf txids;     /* 32 bytes per transaction, block order */
    nodsig_buf wtxids;
    nodsig_buf level;     /* scratch for the Merkle tree */
};

nodsig_scan *nodsig_scan_new(void)
{
    nodsig_scan *s = calloc(1, sizeof *s);
    return s;
}

void nodsig_scan_free(nodsig_scan *s)
{
    int c;
    if (s == NULL)
        return;
    for (c = 0; c < NODSIG_CATS; c++)
        free(s->x.recs[c].data);
    free(s->x.pushes.v);
    free(s->x.inner.v);
    free(s->x.leaf.v);
    free(s->inputs);
    free(s->witness.v);
    free(s->txids.data);
    free(s->wtxids.data);
    free(s->level.data);
    free(s);
}

const nodsig_buf *nodsig_scan_records(const nodsig_scan *s, int cat)
{
    return &s->x.recs[cat];
}

const nodsig_stats *nodsig_scan_stats(const nodsig_scan *s)
{
    return &s->x.stats;
}

/* ------------------------------------------------------------------ */
/* the refusals, with the reference's words                            */
/* ------------------------------------------------------------------ */

static int refuse(char *err, size_t errlen, const char *msg)
{
    if (err && errlen)
        snprintf(err, errlen, "%s", msg);
    return 1;
}

static int refuse_short(char *err, size_t errlen, const char *what)
{
    if (err && errlen)
        snprintf(err, errlen, "bytes ended while reading %s", what);
    return 1;
}

static int refuse_short_i(char *err, size_t errlen, const char *kind,
                          uint64_t i, const char *what)
{
    if (err && errlen)
        snprintf(err, errlen, "bytes ended while reading %s %llu: %s",
                 kind, (unsigned long long)i, what);
    return 1;
}

static int refuse_short_ij(char *err, size_t errlen, uint64_t i, uint64_t j)
{
    if (err && errlen)
        snprintf(err, errlen, "bytes ended while reading input %llu: "
                 "witness item %llu", (unsigned long long)i,
                 (unsigned long long)j);
    return 1;
}

/* blockparse.read_compactsize. Returns 0 and advances *pos, or 1 with
 * the reference's message. */
static int compactsize(const uint8_t *buf, size_t n, size_t *pos,
                       uint64_t *value, char *err, size_t errlen)
{
    size_t p = *pos;
    uint8_t b;
    int width, k;
    if (p >= n)
        return refuse(err, errlen, "bytes ended where a compact size was expected");
    b = buf[p++];
    if (b < 253) {
        *value = b;
        *pos = p;
        return 0;
    }
    width = b == 253 ? 2 : b == 254 ? 4 : 8;
    if (p + width > n)
        return refuse(err, errlen, "bytes ended inside a compact size");
    *value = 0;
    for (k = 0; k < width; k++)
        *value |= (uint64_t)buf[p + k] << (8 * k);
    *pos = p + width;
    return 0;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16
         | (uint32_t)p[3] << 24;
}

/* blockparse.merkle_root over `count` 32-byte ids in `ids`, into `out`.
 * `scratch` is a buffer this borrows. Returns 0, or 3 out of memory. */
static int merkle_root(nodsig_buf *scratch, const uint8_t *ids, size_t count,
                       uint8_t out[32])
{
    size_t n = count, i;
    uint8_t pair[64];
    scratch->len = 0;
    if (nodsig_buf_append(scratch, ids, count * 32))
        return 3;
    while (n > 1) {
        if (n % 2) {
            if (nodsig_buf_append(scratch, scratch->data + (n - 1) * 32, 32))
                return 3;
            n++;
        }
        for (i = 0; i < n; i += 2) {
            memcpy(pair, scratch->data + i * 32, 64);
            nodsig_sha256d(pair, 64, scratch->data + (i / 2) * 32);
        }
        n /= 2;
        scratch->len = n * 32;
    }
    memcpy(out, scratch->data, 32);
    return 0;
}

static int grow_inputs(nodsig_scan *s)
{
    if (s->n_inputs == s->cap_inputs) {
        size_t cap = s->cap_inputs ? s->cap_inputs * 2 : 256;
        input_t *v = realloc(s->inputs, cap * sizeof *v);
        if (v == NULL)
            return 3;
        s->inputs = v;
        s->cap_inputs = cap;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* the block                                                           */
/* ------------------------------------------------------------------ */

int nodsig_scan_block(nodsig_scan *s, const uint8_t *raw, size_t len,
                      uint32_t height, const uint8_t *expect_hash,
                      int extract, nodsig_facts *facts,
                      char *err, size_t errlen)
{
    size_t pos, prologue, base = 0;
    uint64_t n_tx, t;
    int c, r;
    uint8_t hash[32], root[32];
    nodsig_sha256_ctx ids, wids;
    /* the coinbase's facts for the witness commitment */
    const uint8_t *commitment = NULL;
    int cb_is_coinbase = 0, has_witness = 0;
    size_t cb_wit_count = 0, cb_wit0_len = 0;
    const uint8_t *cb_wit0 = NULL;

    for (c = 0; c < NODSIG_CATS; c++)
        s->x.recs[c].len = 0;
    memset(&s->x.stats, 0, sizeof s->x.stats);
    s->x.height[0] = (uint8_t)(height >> 16);
    s->x.height[1] = (uint8_t)(height >> 8);
    s->x.height[2] = (uint8_t)height;
    s->txids.len = s->wtxids.len = 0;
    if (err && errlen)
        err[0] = 0;

    /* blockparse.block_id, then parse_header */
    if (len < 80) {
        if (err && errlen)
            snprintf(err, errlen, "a block is at least 80 bytes of header, "
                     "got %llu", (unsigned long long)len);
        return 1;
    }
    nodsig_sha256d(raw, 80, hash);
    if (expect_hash && memcmp(hash, expect_hash, 32) != 0)
        return 2;
    if (facts) {
        memcpy(facts->hash, hash, 32);
        facts->version = le32(raw);
        memcpy(facts->prev_hash, raw + 4, 32);
        memcpy(facts->merkle_root, raw + 36, 32);
        facts->time = le32(raw + 68);
        facts->bits = le32(raw + 72);
        facts->nonce = le32(raw + 76);
        facts->size = len;
        facts->coinbase_script = NULL;
        facts->coinbase_len = 0;
        facts->coinbase_is_coinbase = 0;
    }
    pos = 80;
    if (compactsize(raw, len, &pos, &n_tx, err, errlen))
        return 1;
    prologue = pos;
    nodsig_sha256_init(&ids);
    nodsig_sha256_init(&wids);

    for (t = 0; t < n_tx; t++) {
        size_t start = pos, body_start, body_end;
        uint64_t n_in, n_out, i, j;
        int segwit;
        uint8_t txid[32], wtxid[32];
        int is_coinbase;

        /* blockparse.parse_tx */
        if (pos + 4 > len)
            return refuse_short(err, errlen, "the transaction version");
        pos += 4;
        if (pos >= len)
            return refuse(err, errlen, "bytes ended after the transaction version");
        segwit = raw[pos] == 0x00;
        if (segwit) {
            if (pos + 2 > len)
                return refuse_short(err, errlen, "the SegWit marker and flag");
            if (raw[pos + 1] != 0x01) {
                if (err && errlen)
                    snprintf(err, errlen, "unknown SegWit flag 0x%02x", raw[pos + 1]);
                return 1;
            }
            pos += 2;
            has_witness = 1;
        }
        body_start = pos;
        if (compactsize(raw, len, &pos, &n_in, err, errlen))
            return 1;
        if (n_in == 0)
            return refuse(err, errlen, "transaction with zero inputs");
        s->n_inputs = 0;
        s->witness.len = 0;
        for (i = 0; i < n_in; i++) {
            uint64_t script_len;
            input_t *in;
            if (pos + 36 > len)
                return refuse_short_i(err, errlen, "input", i, "previous txid");
            if ((r = grow_inputs(s)))
                return r;
            in = &s->inputs[s->n_inputs++];
            in->prev_txid = raw + pos;
            in->prev_vout = le32(raw + pos + 32);
            pos += 36;
            if (pos >= len)
                return refuse_short_i(err, errlen, "input", i, "scriptSig");
            if (raw[pos] < 0xFD) {
                script_len = raw[pos];
                pos += 1;
            } else if (compactsize(raw, len, &pos, &script_len, err, errlen)) {
                return 1;
            }
            if (script_len > len - pos || pos + script_len + 4 > len)
                return refuse_short_i(err, errlen, "input", i, "scriptSig");
            in->script_sig = raw + pos;
            in->sig_len = (size_t)script_len;
            in->wit_start = in->wit_count = 0;
            pos += (size_t)script_len + 4;       /* the script and the sequence */
        }
        is_coinbase = n_in == 1 && s->inputs[0].prev_vout == 0xFFFFFFFF;
        if (is_coinbase) {
            static const uint8_t zero32[32] = {0};
            is_coinbase = memcmp(s->inputs[0].prev_txid, zero32, 32) == 0;
        }
        if (t == 0) {
            cb_is_coinbase = is_coinbase;
            if (facts) {
                facts->coinbase_script = s->inputs[0].script_sig;
                facts->coinbase_len = s->inputs[0].sig_len;
                facts->coinbase_is_coinbase = is_coinbase;
            }
        }

        if (compactsize(raw, len, &pos, &n_out, err, errlen))
            return 1;
        for (i = 0; i < n_out; i++) {
            uint64_t spk_len;
            if (pos + 8 > len)
                return refuse_short_i(err, errlen, "output", i, "value");
            pos += 8;
            if (pos >= len)
                return refuse_short_i(err, errlen, "output", i, "scriptPubKey");
            if (raw[pos] < 0xFD) {
                spk_len = raw[pos];
                pos += 1;
            } else if (compactsize(raw, len, &pos, &spk_len, err, errlen)) {
                return 1;
            }
            if (spk_len > len - pos)
                return refuse_short_i(err, errlen, "output", i, "scriptPubKey");
            if (t == 0 && spk_len >= 38 && raw[pos] == 0x6A && raw[pos + 1] == 0x24
                    && raw[pos + 2] == 0xaa && raw[pos + 3] == 0x21
                    && raw[pos + 4] == 0xa9 && raw[pos + 5] == 0xed)
                commitment = raw + pos + 6;          /* the LAST one wins */
            if (extract && nodsig_extract_output(&s->x, raw + pos, (size_t)spk_len))
                return 3;
            pos += (size_t)spk_len;
        }
        body_end = pos;

        if (segwit) {
            for (i = 0; i < n_in; i++) {
                uint64_t n_items;
                input_t *in = &s->inputs[i];
                if (pos >= len)
                    return refuse_short_i(err, errlen, "input", i, "witness");
                if (raw[pos] < 0xFD) {
                    n_items = raw[pos];
                    pos += 1;
                } else if (compactsize(raw, len, &pos, &n_items, err, errlen)) {
                    return 1;
                }
                in->wit_start = s->witness.len;
                for (j = 0; j < n_items; j++) {
                    uint64_t item_len;
                    if (pos >= len)
                        return refuse_short_ij(err, errlen, i, j);
                    if (raw[pos] < 0xFD) {
                        item_len = raw[pos];
                        pos += 1;
                    } else if (compactsize(raw, len, &pos, &item_len, err, errlen)) {
                        return 1;
                    }
                    if (item_len > len - pos)
                        return refuse_short_ij(err, errlen, i, j);
                    if (nodsig_spans_push(&s->witness, raw + pos, (size_t)item_len))
                        return 3;
                    pos += (size_t)item_len;
                }
                in->wit_count = (size_t)n_items;
            }
        }
        if (pos + 4 > len)
            return refuse_short(err, errlen, "the transaction locktime");
        pos += 4;

        /* the ids: txid over the stripped serialization, wtxid over all */
        if (segwit) {
            nodsig_sha256_ctx h;
            uint8_t inner[32];
            nodsig_sha256_init(&h);
            nodsig_sha256_update(&h, raw + start, 4);
            nodsig_sha256_update(&h, raw + body_start, body_end - body_start);
            nodsig_sha256_update(&h, raw + pos - 4, 4);
            nodsig_sha256_final(&h, inner);
            nodsig_sha256(inner, 32, txid);
            nodsig_sha256d(raw + start, pos - start, wtxid);
            base += 8 + (body_end - body_start);
        } else {
            nodsig_sha256d(raw + start, pos - start, txid);
            memcpy(wtxid, txid, 32);
            base += pos - start;
        }
        if (nodsig_buf_append(&s->txids, txid, 32)
                || nodsig_buf_append(&s->wtxids, wtxid, 32))
            return 3;
        nodsig_sha256_update(&ids, txid, 32);
        nodsig_sha256_update(&wids, wtxid, 32);
        if (t == 0 && segwit) {
            cb_wit_count = s->inputs[0].wit_count;
            if (cb_wit_count) {
                cb_wit0 = s->witness.v[s->inputs[0].wit_start].p;
                cb_wit0_len = s->witness.v[s->inputs[0].wit_start].n;
            }
        }

        /* reveal_archive.block_records: the inputs, coinbase excepted */
        s->x.stats.transactions++;
        if (extract && !is_coinbase) {
            for (i = 0; i < n_in; i++) {
                input_t *in = &s->inputs[i];
                s->x.stats.inputs++;
                if (nodsig_extract_input(&s->x, in->script_sig, in->sig_len,
                                         s->witness.v + in->wit_start,
                                         in->wit_count))
                    return 3;
            }
        }
    }

    /* blockparse.parse_block: the three checks */
    if (pos != len) {
        if (err && errlen)
            snprintf(err, errlen, "%llu trailing bytes after the last "
                     "transaction", (unsigned long long)(len - pos));
        return 1;
    }
    if (n_tx == 0)
        return refuse(err, errlen, "a block carries at least the coinbase");
    if ((r = merkle_root(&s->level, s->txids.data, (size_t)n_tx, root)))
        return r;
    if (memcmp(root, raw + 36, 32) != 0)
        return refuse(err, errlen, "Merkle root mismatch: the transactions do "
                      "not match the header (corrupted bytes?)");

    /* blockparse._verify_witness_commitment */
    if (commitment != NULL || has_witness) {
        uint8_t wroot[32], probe[64], want[32];
        static const uint8_t zero32[32] = {0};
        if (!cb_is_coinbase)
            return refuse(err, errlen, "block with witness data whose first "
                          "transaction is not the coinbase");
        if (commitment == NULL)
            return refuse(err, errlen, "block with witness data but no witness "
                          "commitment in the coinbase");
        memcpy(s->wtxids.data, zero32, 32);      /* the coinbase's own slot */
        if ((r = merkle_root(&s->level, s->wtxids.data, (size_t)n_tx, wroot)))
            return r;
        memcpy(probe, wroot, 32);
        if (!has_witness) {
            memcpy(probe + 32, zero32, 32);
            nodsig_sha256d(probe, 64, want);
            if (memcmp(want, commitment, 32) != 0)
                return refuse(err, errlen,
                    "the coinbase commits to witness data this block does not "
                    "carry, and the commitment does not cover the transactions "
                    "as delivered: the witnesses were stripped in transit (the "
                    "commitment is under the Merkle root and survives; they "
                    "are not)");
        } else {
            if (cb_wit_count != 1 || cb_wit0_len != 32)
                return refuse(err, errlen, "coinbase witness is not the single "
                              "32-byte reserved value required by BIP 141");
            memcpy(probe + 32, cb_wit0, 32);
            nodsig_sha256d(probe, 64, want);
            if (memcmp(want, commitment, 32) != 0)
                return refuse(err, errlen, "witness commitment mismatch: the "
                              "witness bytes do not match the coinbase "
                              "(corrupted bytes?)");
        }
    }

    if (facts) {
        facts->tx_count = n_tx;
        facts->weight = 3 * (prologue + base) + len;
        nodsig_sha256_final(&ids, facts->txids_sha256);
        nodsig_sha256_final(&wids, facts->wtxids_sha256);
    }
    return 0;
}
