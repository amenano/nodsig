/* nodsig_scan.h — the native kernel of the reveal archive's scan.
 *
 * One block in, the archive's records out. `nodsig_scan_block` walks the
 * raw bytes of a block once: it verifies what `blockparse.parse_block`
 * verifies (the header's hash against the one asked for, the Merkle root,
 * the witness commitment, every transaction's shape), and along the way
 * does what `reveal_archive.block_records` does: the keys an output
 * publishes and the programs it creates, and for every non-coinbase
 * input the keys, the candidate scripts, the keys inside them, the
 * taproot internal and leaf keys, the program a P2SH-P2WSH spend names.
 * It appends one record `digest | byte | height` per sighting to the
 * buffer of its category, in the archive's own record layout, and moves
 * the same counters the scan moves.
 *
 * The contract is the multiset of records and the counters: the order
 * inside a buffer is the walk's (a run is sorted and reduced before it is
 * written) and is not promised. Every rule is ported line by line from
 * the Python module named beside it (blockparse, keyforms, sightings,
 * reveal_archive), which stays the reference: if the two disagree the
 * Python is right, and the suite compares them on the conformance
 * vectors (tests/fixtures/scan).
 *
 * Plain C99, no dependency, no global state: a `nodsig_scan` holds the
 * buffers and the scratch arrays of one caller and is reused block after
 * block. The bytes are untrusted: every read is bounds-checked and a
 * short or malformed block is a refusal (return 1, message in `err`),
 * never a read past the buffer; no allocation follows a count the bytes
 * declare before the bytes are there.
 */
#ifndef NODSIG_SCAN_H
#define NODSIG_SCAN_H

#include <stddef.h>
#include <stdint.h>

/* The record categories, in the order of reveal_archive.RUN_CATS. */
enum {
    NODSIG_KEYS = 0,
    NODSIG_SCRIPTS20 = 1,
    NODSIG_SCRIPTS32 = 2,
    NODSIG_PROGRAMS20 = 3,
    NODSIG_PROGRAMS32 = 4,
    NODSIG_CATS = 5
};

/* A growable byte buffer: the records of one category. */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} nodsig_buf;

/* The counters one block moves, from zero (reveal_archive.run_scan's
 * `stats` plus sightings.new_filter_stats). */
typedef struct {
    uint64_t transactions;
    uint64_t inputs;
    uint64_t malformed_scriptsig;
    uint64_t revelations;
    uint64_t program_outputs;
    uint64_t nested_programs;
    uint64_t out_keys;
    uint64_t control_or_annex;
    uint64_t unparsed_candidates;
} nodsig_stats;

/* What a parser must agree on about a block (the header, the two sizes,
 * a digest over the txids and over the wtxids in block order, internal
 * byte order). Hashes are in internal (little-endian) byte order. */
typedef struct {
    uint8_t hash[32];
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    uint32_t version;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
    uint64_t tx_count;
    uint64_t size;
    uint64_t weight;
    uint8_t txids_sha256[32];
    uint8_t wtxids_sha256[32];
    /* the first transaction's first input: its scriptSig (a view into
     * the block) and whether the transaction is a coinbase, for the
     * header archive (headers.coinbase_script) */
    const uint8_t *coinbase_script;
    size_t coinbase_len;
    int coinbase_is_coinbase;
} nodsig_facts;

typedef struct nodsig_scan nodsig_scan;

nodsig_scan *nodsig_scan_new(void);
void nodsig_scan_free(nodsig_scan *s);

/* Scan one block. `expect_hash` (32 bytes, internal order) may be NULL.
 * With `extract` zero the walk verifies and reports the facts but
 * appends no record (the parser alone). Returns 0 on success, 1 on a
 * refusal (a message in `err`, `errlen` bytes long), 2 when the header
 * does not hash to `expect_hash`, 3 when out of memory. On success the
 * records of the block are in `nodsig_scan_records(s, cat)` and its
 * counters in `nodsig_scan_stats(s)` until the next call. */
int nodsig_scan_block(nodsig_scan *s, const uint8_t *raw, size_t len,
                      uint32_t height, const uint8_t *expect_hash,
                      int extract, nodsig_facts *facts,
                      char *err, size_t errlen);

const nodsig_buf *nodsig_scan_records(const nodsig_scan *s, int cat);
const nodsig_stats *nodsig_scan_stats(const nodsig_scan *s);

/* The record widths per category: digest bytes + 1 + 3. */
int nodsig_digest_len(int cat);

#endif
