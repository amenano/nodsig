/* nodsig_kway.c — see nodsig_kway.h. */
#include "nodsig_kway.h"

#include <stdlib.h>
#include <string.h>

/* The cursor of one piece: where its next record is and where it ends. */
typedef struct {
    const uint8_t *at;
    const uint8_t *end;
} piece_t;

/* A binary min-heap of piece indices ordered by their head record. The
 * whole record is the order, as it is for the reference's sort of bytes
 * objects; two heads that compare equal are identical bytes, so which
 * one leaves first cannot change the output. */
typedef struct {
    piece_t *p;
    size_t *heap;
    size_t n;
    size_t rec;
} heap_t;

static inline int head_lt(const heap_t *h, size_t a, size_t b)
{
    return memcmp(h->p[a].at, h->p[b].at, h->rec) < 0;
}

static void sift_down(heap_t *h, size_t i)
{
    size_t n = h->n;
    size_t *heap = h->heap;
    size_t x = heap[i];
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        size_t best = x;
        if (l < n && head_lt(h, heap[l], best)) { m = l; best = heap[l]; }
        if (r < n && head_lt(h, heap[r], best)) { m = r; best = heap[r]; }
        if (m == i)
            break;
        heap[i] = heap[m];
        i = m;
    }
    heap[i] = x;
}

int64_t nodsig_kway_fuse(const uint8_t *const *pieces, const size_t *counts,
                         size_t k, size_t rec, size_t dedup_len, int rule,
                         uint8_t *out, uint64_t *dups)
{
    piece_t *p;
    size_t *heap;
    heap_t h;
    size_t i, n = 0, w = 0, tail = 0;
    uint8_t *o = out;         /* where the next record goes                 */
    uint8_t *cur = NULL;      /* the pending record, already in `out`      */
    uint64_t d = 0;

    *dups = 0;
    if (rec == 0 || dedup_len > rec || rule < NODSIG_KWAY_COUNT
            || rule > NODSIG_KWAY_MAX_MIN)
        return -2;
    if (rule >= NODSIG_KWAY_OR_MIN) {
        if (rec < 4)
            return -2;
        w = rec - 4;          /* the byte the rule combines                */
        tail = 3;             /* the bytes it takes the minimum of         */
    }
    if (k == 0)
        return 0;
    p = malloc(k * sizeof *p);
    heap = malloc(k * sizeof *heap);
    if (p == NULL || heap == NULL) {
        free(p);
        free(heap);
        return -3;
    }
    for (i = 0; i < k; i++) {
        if (counts[i] == 0)
            continue;
        p[n].at = pieces[i];
        p[n].end = pieces[i] + counts[i] * rec;
        heap[n] = n;
        n++;
    }
    h.p = p;
    h.heap = heap;
    h.n = n;
    h.rec = rec;
    for (i = n; i-- > 0;)
        sift_down(&h, i);

    while (h.n) {
        size_t top = heap[0];
        const uint8_t *r = p[top].at;

        if (cur != NULL && memcmp(cur, r, dedup_len) == 0) {
            d++;
            switch (rule) {
            case NODSIG_KWAY_COUNT:
                memcpy(o, r, rec);      /* kept, and the one to compare next */
                cur = o;
                o += rec;
                break;
            case NODSIG_KWAY_LAST:
                memcpy(cur, r, rec);    /* the later record wins             */
                break;
            case NODSIG_KWAY_OR_MIN:
                cur[w] |= r[w];
                if (memcmp(r + w + 1, cur + w + 1, tail) < 0)
                    memcpy(cur + w + 1, r + w + 1, tail);
                break;
            default:                    /* NODSIG_KWAY_MAX_MIN               */
                if (r[w] > cur[w])
                    cur[w] = r[w];
                if (memcmp(r + w + 1, cur + w + 1, tail) < 0)
                    memcpy(cur + w + 1, r + w + 1, tail);
                break;
            }
        } else {
            memcpy(o, r, rec);
            cur = o;
            o += rec;
        }

        /* Advance the piece; refuse a piece that turns out unsorted. */
        p[top].at += rec;
        if (p[top].at < p[top].end) {
            if (memcmp(r, p[top].at, rec) > 0) {
                free(p);
                free(heap);
                return -1;
            }
        } else {
            heap[0] = heap[--h.n];
            if (h.n == 0)
                break;
        }
        sift_down(&h, 0);
    }
    free(p);
    free(heap);
    *dups = d;
    return (int64_t)(o - out);
}
