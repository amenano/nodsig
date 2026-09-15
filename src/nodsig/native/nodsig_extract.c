/* nodsig_extract.c — see nodsig_extract.h. Each function names the
 * Python it is ported from; the rules are theirs, not this file's. */
#include "nodsig_extract.h"
#include "nodsig_hash.h"

#include <stdlib.h>
#include <string.h>

/* sightings.py: the provenance and form bits of a `keys` record. */
#define FLAG_SIG 1
#define FLAG_WIT 2
#define FLAG_INNER_SIG 4
#define FLAG_INNER_WIT 8
#define FLAG_UNCOMPRESSED 16
#define FLAG_OUT 32
#define FLAG_OTHER_FACE 64
#define FLAG_XONLY 128
#define MAX_INNER_KEYS 255

/* reveal_archive.py: the byte of a `programs*` record. */
#define PROGRAM_OUTPUT 1
#define PROGRAM_NESTED 2

/* sightings.MIN_KEY_OUTPUT */
#define MIN_KEY_OUTPUT 35

/* ------------------------------------------------------------------ */
/* growable containers                                                 */
/* ------------------------------------------------------------------ */

int nodsig_buf_append(nodsig_buf *b, const uint8_t *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n)
            cap *= 2;
        uint8_t *d = realloc(b->data, cap);
        if (d == NULL)
            return -2;
        b->data = d;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

int nodsig_spans_push(nodsig_spans *a, const uint8_t *p, size_t n)
{
    if (a->len == a->cap) {
        size_t cap = a->cap ? a->cap * 2 : 64;
        nodsig_span *v = realloc(a->v, cap * sizeof *v);
        if (v == NULL)
            return -2;
        a->v = v;
        a->cap = cap;
    }
    a->v[a->len].p = p;
    a->v[a->len].n = n;
    a->len++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* blockparse._walk_pushes                                             */
/* ------------------------------------------------------------------ */

int nodsig_walk_pushes(const uint8_t *script, size_t n, nodsig_spans *out)
{
    size_t pos = 0;
    out->len = 0;
    while (pos < n) {
        uint8_t op = script[pos++];
        uint64_t length;
        if (op <= 75) {
            if (op == 0)                       /* OP_0: no data from the bytes */
                continue;
            length = op;                       /* direct push: opcode is the length */
        } else if (op == 76) {                 /* OP_PUSHDATA1 */
            if (pos + 1 > n)
                return -1;
            length = script[pos];
            pos += 1;
        } else if (op == 77) {                 /* OP_PUSHDATA2 */
            if (pos + 2 > n)
                return -1;
            length = (uint64_t)script[pos] | (uint64_t)script[pos + 1] << 8;
            pos += 2;
        } else if (op == 78) {                 /* OP_PUSHDATA4 */
            if (pos + 4 > n)
                return -1;
            length = (uint64_t)script[pos] | (uint64_t)script[pos + 1] << 8
                   | (uint64_t)script[pos + 2] << 16 | (uint64_t)script[pos + 3] << 24;
            pos += 4;
        } else {                               /* not a data push: skip */
            continue;
        }
        if (length > n - pos)
            return -1;
        if (nodsig_spans_push(out, script + pos, (size_t)length))
            return -2;
        pos += (size_t)length;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* records                                                             */
/* ------------------------------------------------------------------ */

static int record(nodsig_extract *x, int cat, const uint8_t *digest,
                  uint8_t byte)
{
    uint8_t rec[36];
    int dl = nodsig_digest_len(cat);
    memcpy(rec, digest, dl);
    rec[dl] = byte;
    memcpy(rec + dl + 1, x->height, 3);
    return nodsig_buf_append(&x->recs[cat], rec, dl + 4);
}

/* keyforms.looks_like_key */
static int looks_like_key(const uint8_t *p, size_t n)
{
    return (n == 33 && (p[0] == 0x02 || p[0] == 0x03))
        || (n == 65 && (p[0] == 0x04 || p[0] == 0x06 || p[0] == 0x07));
}

/* sightings.key_records, with keyforms.canonical_key inlined. Returns
 * 1 when `item` was a key (and, if `seen` is not NULL, leaves in it the
 * digest of the form seen: hash160(item)), 0 when it was not, -2 out of
 * memory. */
static int key_records(nodsig_extract *x, const uint8_t *p, size_t n,
                       uint8_t provenance, int xonly, uint8_t *seen)
{
    uint8_t canon[20], other[20], key33[33];
    if (xonly && n == 32) {
        key33[0] = 0x02;
        memcpy(key33 + 1, p, 32);
        nodsig_hash160(key33, 33, canon);
        x->stats.revelations++;
        return record(x, NODSIG_KEYS, canon, provenance | FLAG_XONLY) ? -2 : 1;
    }
    if (!looks_like_key(p, n))
        return 0;
    if (n == 33) {
        nodsig_hash160(p, 33, canon);
        if (seen)
            memcpy(seen, canon, 20);
        x->stats.revelations++;
        return record(x, NODSIG_KEYS, canon, provenance) ? -2 : 1;
    }
    /* keyforms.compressed_of: the 33-byte form of a 65-byte key */
    key33[0] = 0x02 | (p[64] & 1);
    memcpy(key33 + 1, p + 1, 32);
    nodsig_hash160(key33, 33, canon);
    nodsig_hash160(p, 65, other);              /* the digest of the form seen */
    if (seen)
        memcpy(seen, other, 20);
    x->stats.revelations += 2;
    if (record(x, NODSIG_KEYS, other, provenance | FLAG_UNCOMPRESSED)
            || record(x, NODSIG_KEYS, canon, FLAG_OTHER_FACE))
        return -2;
    return 1;
}

/* sightings.is_control_block */
static int is_control_block(const uint8_t *p, size_t n)
{
    return n >= 33 && (n - 33) % 32 == 0 && (p[0] & 0xfe) == 0xc0;
}

/* sightings.cannot_be_script */
static int cannot_be_script(nodsig_extract *x, const uint8_t *p, size_t n,
                            size_t witness_len)
{
    if (is_control_block(p, n) || (witness_len >= 2 && n >= 1 && p[0] == 0x50)) {
        x->stats.control_or_annex++;
        return 1;
    }
    return 0;
}

/* sightings.script_records: the record of a candidate script and of
 * the keys inside it. `digest` may be given (hash160 of the script the
 * caller already holds, scripts20 only). */
static int script_records(nodsig_extract *x, const uint8_t *script, size_t n,
                          int cat, uint8_t inner_flag, const uint8_t *digest)
{
    uint8_t own[32];
    size_t i, found = 0;
    int r = nodsig_walk_pushes(script, n, &x->inner);
    if (r == -2)
        return -2;
    if (r == -1) {
        x->stats.unparsed_candidates++;
        x->inner.len = 0;
    }
    if (digest == NULL) {
        if (cat == NODSIG_SCRIPTS20)
            nodsig_hash160(script, n, own);
        else
            nodsig_sha256(script, n, own);
        digest = own;
    }
    /* The script's record comes first in the reference; the order is
     * not a promise, but keeping it costs nothing. */
    x->stats.revelations++;
    if (record(x, cat, digest, 0))
        return -2;
    size_t at = x->recs[cat].len - (nodsig_digest_len(cat) + 4);
    for (i = 0; i < x->inner.len; i++) {
        r = key_records(x, x->inner.v[i].p, x->inner.v[i].n, inner_flag, 0, NULL);
        if (r < 0)
            return -2;
        found += r;
    }
    x->recs[cat].data[at + nodsig_digest_len(cat)] =
        (uint8_t)(found < MAX_INNER_KEYS ? found : MAX_INNER_KEYS);
    return 0;
}

/* sightings.taproot_body: the witness without its annex. */
static size_t taproot_body(const nodsig_span *w, size_t n)
{
    if (n >= 2 && w[n - 1].n >= 1 && w[n - 1].p[0] == 0x50)
        return n - 1;
    return n;
}

/* sightings.leaf_xonly_keys: walked by opcode, with the reference's own
 * truncation (a push running past the end yields the bytes there are,
 * and the index moves past the end, which ends the walk). */
static int leaf_xonly_keys(nodsig_extract *x, const uint8_t *leaf, size_t n)
{
    size_t i = 0;
    x->leaf.len = 0;
    while (i < n) {
        uint8_t op = leaf[i];
        size_t start, want, next;
        if (op >= 1 && op <= 75) {
            start = i + 1; want = op; next = i + 1 + op;
        } else if (op == 0x4c && i + 1 < n) {
            want = leaf[i + 1]; start = i + 2; next = i + 2 + want;
        } else if (op == 0x4d && i + 2 < n) {
            want = (size_t)leaf[i + 1] | (size_t)leaf[i + 2] << 8;
            start = i + 3; next = i + 3 + want;
        } else if (op == 0x4e && i + 4 < n) {
            want = (size_t)leaf[i + 1] | (size_t)leaf[i + 2] << 8
                 | (size_t)leaf[i + 3] << 16 | (size_t)leaf[i + 4] << 24;
            start = i + 5; next = i + 5 + want;
        } else {
            i += 1;
            continue;
        }
        size_t have = start <= n ? n - start : 0;
        size_t got = want < have ? want : have;
        i = next;
        if (got == 32 && i < n
                && (leaf[i] == 0xac || leaf[i] == 0xad || leaf[i] == 0xba))
            if (nodsig_spans_push(&x->leaf, leaf + start, 32))
                return -2;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* outputs: extract_output_revelations + output_program                */
/* ------------------------------------------------------------------ */

int nodsig_extract_output(nodsig_extract *x, const uint8_t *spk, size_t n)
{
    int r;
    /* sightings.output_keys */
    if (n >= MIN_KEY_OUTPUT) {
        if ((n == 35 || n == 67) && spk[0] == n - 2 && spk[n - 1] == 0xac) {
            r = key_records(x, spk + 1, n - 2, FLAG_OUT, 0, NULL);
            if (r < 0)
                return -2;
            x->stats.out_keys += r;
        } else if (n >= 37 && spk[n - 1] == 0xae
                   && spk[n - 2] >= 0x51 && spk[n - 2] <= 0x60
                   && spk[0] >= 0x51 && spk[0] <= 0x60) {
            r = nodsig_walk_pushes(spk + 1, n - 3, &x->pushes);
            if (r == -2)
                return -2;
            if (r == 0) {
                size_t i;
                for (i = 0; i < x->pushes.len; i++) {
                    r = key_records(x, x->pushes.v[i].p, x->pushes.v[i].n,
                                    FLAG_OUT, 0, NULL);
                    if (r < 0)
                        return -2;
                    x->stats.out_keys += r;
                }
            }
        }
    }
    /* reveal_archive.output_program */
    if (n == 23 && spk[0] == 0xA9 && spk[1] == 0x14 && spk[22] == 0x87) {
        x->stats.program_outputs++;
        return record(x, NODSIG_PROGRAMS20, spk + 2, PROGRAM_OUTPUT);
    }
    if (n == 34 && spk[0] == 0x00 && spk[1] == 0x20) {
        x->stats.program_outputs++;
        return record(x, NODSIG_PROGRAMS32, spk + 2, PROGRAM_OUTPUT);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* inputs: scriptsig_pushes + extract_revelations + nested_program     */
/* ------------------------------------------------------------------ */

int nodsig_extract_input(nodsig_extract *x, const uint8_t *script_sig,
                         size_t sig_len, const nodsig_span *witness,
                         size_t n_witness)
{
    size_t i;
    int r;
    uint8_t seen[20];
    int last_is_key = 0;

    /* blockparse.scriptsig_pushes: malformed ones counted, then empty */
    r = nodsig_walk_pushes(script_sig, sig_len, &x->pushes);
    if (r == -2)
        return -2;
    if (r == -1) {
        x->stats.malformed_scriptsig++;
        x->pushes.len = 0;
    }
    const nodsig_span *sig = x->pushes.v;
    size_t n_sig = x->pushes.len;

    /* every key-shaped push of the scriptSig; `seen` is the last push's */
    for (i = 0; i < n_sig; i++) {
        r = key_records(x, sig[i].p, sig[i].n, FLAG_SIG, 0, seen);
        if (r < 0)
            return -2;
        last_is_key = r;
    }
    /* sightings.witness_key_records: every key-shaped witness item */
    for (i = 0; i < n_witness; i++)
        if (key_records(x, witness[i].p, witness[i].n, FLAG_WIT, 0, NULL) < 0)
            return -2;

    /* the candidates: the last scriptSig push, the last witness item */
    if (n_sig && !cannot_be_script(x, sig[n_sig - 1].p, sig[n_sig - 1].n, 0))
        if (script_records(x, sig[n_sig - 1].p, sig[n_sig - 1].n,
                           NODSIG_SCRIPTS20, FLAG_INNER_SIG,
                           last_is_key ? seen : NULL))
            return -2;
    if (n_witness && !cannot_be_script(x, witness[n_witness - 1].p,
                                       witness[n_witness - 1].n, n_witness))
        if (script_records(x, witness[n_witness - 1].p, witness[n_witness - 1].n,
                           NODSIG_SCRIPTS32, FLAG_INNER_WIT, NULL))
            return -2;

    /* a taproot script path: the internal key, then the leaf's keys */
    size_t body = taproot_body(witness, n_witness);
    if (body >= 2 && is_control_block(witness[body - 1].p, witness[body - 1].n)) {
        if (key_records(x, witness[body - 1].p + 1, 32, FLAG_WIT, 1, NULL) < 0)
            return -2;
        if (leaf_xonly_keys(x, witness[body - 2].p, witness[body - 2].n))
            return -2;
        for (i = 0; i < x->leaf.len; i++)
            if (key_records(x, x->leaf.v[i].p, 32, FLAG_INNER_WIT, 1, NULL) < 0)
                return -2;
    }

    /* reveal_archive.nested_program */
    if (n_witness && n_sig) {
        const nodsig_span *last = &sig[n_sig - 1];
        if (last->n == 34 && last->p[0] == 0x00 && last->p[1] == 0x20) {
            x->stats.nested_programs++;
            if (record(x, NODSIG_PROGRAMS32, last->p + 2, PROGRAM_NESTED))
                return -2;
        }
    }
    return 0;
}
