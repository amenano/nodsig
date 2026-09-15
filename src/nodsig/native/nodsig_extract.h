/* nodsig_extract.h — the extraction rules of the scan, in C: the push
 * parser of `blockparse`, the key forms of `keyforms`, the sightings of
 * `sightings`, the output and nested-program rules of `reveal_archive`.
 * Internal to the kernel; see nodsig_scan.h for the public face. */
#ifndef NODSIG_EXTRACT_H
#define NODSIG_EXTRACT_H

#include "nodsig_scan.h"

/* A view into the block's bytes: nothing is copied out of the block. */
typedef struct {
    const uint8_t *p;
    size_t n;
} nodsig_span;

/* A growable array of spans (the pushes of a script, the items of a
 * witness). */
typedef struct {
    nodsig_span *v;
    size_t len;
    size_t cap;
} nodsig_spans;

int nodsig_spans_push(nodsig_spans *a, const uint8_t *p, size_t n);
int nodsig_buf_append(nodsig_buf *b, const uint8_t *p, size_t n);

/* The walk under blockparse.script_pushes / script_pushes_or_none: the
 * data pushes of `script` appended to `out` (emptied first). Returns 0,
 * or -1 when a push claims more bytes than the script has (the script
 * is malformed; `out` is then meaningless), or -2 out of memory. */
int nodsig_walk_pushes(const uint8_t *script, size_t n, nodsig_spans *out);

/* The per-block extraction state: the record buffers, the counters, the
 * height bytes, and the scratch arrays. */
typedef struct {
    nodsig_buf recs[NODSIG_CATS];
    nodsig_stats stats;
    uint8_t height[3];
    nodsig_spans pushes;      /* the scriptSig pushes of the input at hand */
    nodsig_spans inner;       /* the pushes inside a candidate script */
    nodsig_spans leaf;        /* the x-only keys a taproot leaf names */
} nodsig_extract;

/* reveal_archive.extract_output_revelations + output_program on one
 * scriptPubKey. Returns 0, or -2 out of memory. */
int nodsig_extract_output(nodsig_extract *x, const uint8_t *spk, size_t n);

/* blockparse.scriptsig_pushes + reveal_archive.extract_revelations +
 * nested_program on one non-coinbase input: its scriptSig and its
 * witness items. Returns 0, or -2 out of memory. */
int nodsig_extract_input(nodsig_extract *x, const uint8_t *script_sig,
                         size_t sig_len, const nodsig_span *witness,
                         size_t n_witness);

#endif
