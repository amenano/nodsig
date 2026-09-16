/* nodsig_kway.h — the native k-way stage of a fusion's round.
 *
 * One round of `genstore._BulkFusion` in C: k sorted pieces of fixed-width
 * records in, ONE sorted blob out with the equal keys reduced by the
 * fusion's rule, and the number of reductions. The Python stage gathers
 * the pieces (a slab's stretch per source, below a threshold every source
 * has reached), sorts them in one list and reduces the equal keys by
 * column; this does the same by a k-way merge over the pieces, which
 * are each already sorted, and reduces on the way out. Same bytes, same
 * count, which the suite pins on random matrices and the bench pins on a
 * pile of the real shape.
 *
 * WHY. With ~1,200 sources a round holds ~18 k records in ~1,200 pieces
 * of ~15, and a general sort has nothing to bite on: below timsort's
 * minrun the pieces degenerate into binary insertions plus nine levels
 * of merge, ~14 compares a record in Python's object compare (measured
 * ~3 µs a record on the first real 3.0.x fusion). A merge that KNOWS the
 * pieces are sorted pays log2(k) memcmp's a record and nothing per
 * object.
 *
 * THE RULES are `merge_to_file`'s, on the dedup prefix of `dedup_len`
 * bytes: COUNT keeps every record and counts the adjacent equal pairs;
 * LAST keeps the last of an equal group (the greatest record, the
 * pieces being merged in record order); OR_MIN and MAX_MIN are the
 * reveal archive's `_combine_or` / `_combine_scripts`: the group folds
 * onto its first record, the byte at rec-4 OR-ed (or the max), the last
 * three bytes the lexicographic minimum. Each is associative and
 * commutative, so the order equal records meet in does not matter.
 *
 * A piece that is not sorted is refused (-1) rather than merged wrong:
 * the caller then takes the reference road for that round, so the two
 * roads agree on every input, not only the well-formed one. Plain C99,
 * no global state; the pieces are not modified.
 */
#ifndef NODSIG_KWAY_H
#define NODSIG_KWAY_H

#include <stddef.h>
#include <stdint.h>

enum {
    NODSIG_KWAY_COUNT = 0,      /* keep every record, count equal pairs  */
    NODSIG_KWAY_LAST = 1,       /* keep the last of each equal group      */
    NODSIG_KWAY_OR_MIN = 2,     /* byte[rec-4] |=, tail[rec-3:] = min     */
    NODSIG_KWAY_MAX_MIN = 3     /* byte[rec-4] = max, tail[rec-3:] = min  */
};

/* Merge and reduce. `pieces[i]` holds `counts[i]` records of `rec` bytes,
 * sorted; `out` has room for every record (the sum of the pieces); on
 * return `*dups` is the number of reductions. Returns the bytes written,
 * or -1 when a piece is not sorted, -2 when `rule` or the widths are not
 * acceptable (rec < 4 for the combining rules, dedup_len > rec), -3 when
 * memory for the heap cannot be had. */
int64_t nodsig_kway_fuse(const uint8_t *const *pieces, const size_t *counts,
                         size_t k, size_t rec, size_t dedup_len, int rule,
                         uint8_t *out, uint64_t *dups);

#endif
