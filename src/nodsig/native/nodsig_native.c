/* nodsig_native.c — the CPython face of the kernel: `nodsig._native`.
 *
 * Two functions. `scan_block(raw, height, expect_hash=None)`, returning
 *   (0, records, stats, facts)   records: a tuple of five bytes objects
 *                                 in reveal_archive.RUN_CATS order;
 *                                 stats: dict; facts: dict
 *   (1, message)                 the block is refused, as the parser
 *                                 would refuse it, with its words
 *   (2, None)                    the header does not hash to expect_hash
 * MemoryError when the kernel cannot allocate. The Python side
 * (`nodsig.kernel`) turns the codes into the scan's own exceptions, so
 * this module knows nothing of them. The scan context is created per
 * call: its buffers are what `records` copies out of, and a scan holds
 * one block at a time. And `fuse_pieces(pieces, rec, dedup_len, rule)`,
 * one round of a fusion's k-way stage (nodsig_kway.h), described at its
 * definition.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "nodsig_kway.h"
#include "nodsig_scan.h"

static PyObject *py_scan_block(PyObject *self, PyObject *args)
{
    Py_buffer raw;
    unsigned long height;
    PyObject *expect = Py_None;
    const uint8_t *expect_hash = NULL;
    nodsig_scan *s;
    nodsig_facts f;
    char err[512];
    int code, c;
    PyObject *records = NULL, *stats = NULL, *facts = NULL, *result = NULL;
    const nodsig_stats *st;

    (void)self;
    if (!PyArg_ParseTuple(args, "y*k|O", &raw, &height, &expect))
        return NULL;
    if (expect != Py_None) {
        if (!PyBytes_Check(expect) || PyBytes_GET_SIZE(expect) != 32) {
            PyBuffer_Release(&raw);
            PyErr_SetString(PyExc_TypeError, "expect_hash must be 32 bytes or None");
            return NULL;
        }
        expect_hash = (const uint8_t *)PyBytes_AS_STRING(expect);
    }
    if (height > 0xFFFFFFu) {
        PyBuffer_Release(&raw);
        PyErr_SetString(PyExc_ValueError, "height does not fit in three bytes");
        return NULL;
    }
    s = nodsig_scan_new();
    if (s == NULL) {
        PyBuffer_Release(&raw);
        return PyErr_NoMemory();
    }
    code = nodsig_scan_block(s, raw.buf, raw.len, (uint32_t)height, expect_hash,
                             1, &f, err, sizeof err);
    if (code == 3) {
        result = PyErr_NoMemory();
        goto done;
    }
    if (code == 1) {
        result = Py_BuildValue("(is)", 1, err);
        goto done;
    }
    if (code == 2) {
        result = Py_BuildValue("(iO)", 2, Py_None);
        goto done;
    }
    records = PyTuple_New(NODSIG_CATS);
    if (records == NULL)
        goto done;
    for (c = 0; c < NODSIG_CATS; c++) {
        const nodsig_buf *b = nodsig_scan_records(s, c);
        PyObject *o = PyBytes_FromStringAndSize((const char *)b->data, (Py_ssize_t)b->len);
        if (o == NULL)
            goto done;
        PyTuple_SET_ITEM(records, c, o);
    }
    st = nodsig_scan_stats(s);
    stats = Py_BuildValue(
        "{s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K}",
        "transactions", (unsigned long long)st->transactions,
        "inputs", (unsigned long long)st->inputs,
        "malformed_scriptsig", (unsigned long long)st->malformed_scriptsig,
        "revelations", (unsigned long long)st->revelations,
        "program_outputs", (unsigned long long)st->program_outputs,
        "nested_programs", (unsigned long long)st->nested_programs,
        "out_keys", (unsigned long long)st->out_keys,
        "control_or_annex", (unsigned long long)st->control_or_annex,
        "unparsed_candidates", (unsigned long long)st->unparsed_candidates);
    if (stats == NULL)
        goto done;
    facts = Py_BuildValue(
        "{s:y#,s:y#,s:y#,s:k,s:k,s:k,s:k,s:K,s:K,s:K,s:y#,s:y#,s:y#,s:O}",
        "hash", (const char *)f.hash, (Py_ssize_t)32,
        "prev_hash", (const char *)f.prev_hash, (Py_ssize_t)32,
        "merkle_root", (const char *)f.merkle_root, (Py_ssize_t)32,
        "version", (unsigned long)f.version,
        "time", (unsigned long)f.time,
        "bits", (unsigned long)f.bits,
        "nonce", (unsigned long)f.nonce,
        "tx_count", (unsigned long long)f.tx_count,
        "size", (unsigned long long)f.size,
        "weight", (unsigned long long)f.weight,
        "txids_sha256", (const char *)f.txids_sha256, (Py_ssize_t)32,
        "wtxids_sha256", (const char *)f.wtxids_sha256, (Py_ssize_t)32,
        "coinbase_script", (const char *)f.coinbase_script, (Py_ssize_t)f.coinbase_len,
        "coinbase_is_coinbase", f.coinbase_is_coinbase ? Py_True : Py_False);
    if (facts == NULL)
        goto done;
    result = Py_BuildValue("(iOOO)", 0, records, stats, facts);
done:
    Py_XDECREF(records);
    Py_XDECREF(stats);
    Py_XDECREF(facts);
    nodsig_scan_free(s);
    PyBuffer_Release(&raw);
    return result;
}

/* fuse_pieces(pieces, rec, dedup_len, rule) -> (blob, dups) or None.
 * One round of the fusion's k-way stage (nodsig_kway.h): `pieces` is a
 * sequence of bytes-like objects, each a whole number of sorted records.
 * None means a piece was not sorted and the caller takes the reference
 * road for this round; a wrong width or rule is a ValueError. */
static PyObject *py_fuse_pieces(PyObject *self, PyObject *args)
{
    PyObject *seq, *fast = NULL, *blob = NULL, *result = NULL;
    Py_ssize_t rec, dedup_len, k, i, got = 0;
    int rule;
    Py_buffer *bufs = NULL;
    const uint8_t **ptrs = NULL;
    size_t *counts = NULL, total = 0;
    uint64_t dups = 0;
    int64_t written;

    (void)self;
    if (!PyArg_ParseTuple(args, "Onni", &seq, &rec, &dedup_len, &rule))
        return NULL;
    if (rec <= 0 || dedup_len < 0 || dedup_len > rec) {
        PyErr_SetString(PyExc_ValueError, "rec must be positive and dedup_len within it");
        return NULL;
    }
    fast = PySequence_Fast(seq, "pieces must be a sequence");
    if (fast == NULL)
        return NULL;
    k = PySequence_Fast_GET_SIZE(fast);
    if (k > 0) {
        bufs = calloc((size_t)k, sizeof *bufs);
        ptrs = malloc((size_t)k * sizeof *ptrs);
        counts = malloc((size_t)k * sizeof *counts);
        if (bufs == NULL || ptrs == NULL || counts == NULL) {
            PyErr_NoMemory();
            goto done;
        }
    }
    for (i = 0; i < k; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(fast, i);
        if (PyObject_GetBuffer(item, &bufs[got], PyBUF_SIMPLE) < 0)
            goto done;
        got++;
        if (bufs[i].len % rec != 0) {
            PyErr_SetString(PyExc_ValueError, "a piece is not a whole number of records");
            goto done;
        }
        ptrs[i] = bufs[i].buf;
        counts[i] = (size_t)(bufs[i].len / rec);
        total += (size_t)bufs[i].len;
    }
    blob = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)total);
    if (blob == NULL)
        goto done;
    written = nodsig_kway_fuse(ptrs, counts, (size_t)k, (size_t)rec,
                               (size_t)dedup_len, rule,
                               (uint8_t *)PyBytes_AS_STRING(blob), &dups);
    if (written == -1) {
        result = Py_None;
        Py_INCREF(result);
        goto done;
    }
    if (written == -2) {
        PyErr_SetString(PyExc_ValueError, "rule or widths the kernel does not take");
        goto done;
    }
    if (written < 0) {
        PyErr_NoMemory();
        goto done;
    }
    if (_PyBytes_Resize(&blob, (Py_ssize_t)written) < 0)
        goto done;
    result = Py_BuildValue("(OK)", blob, (unsigned long long)dups);
done:
    for (i = 0; i < got; i++)
        PyBuffer_Release(&bufs[i]);
    free(bufs);
    free(ptrs);
    free(counts);
    Py_XDECREF(blob);
    Py_XDECREF(fast);
    return result;
}

static PyMethodDef methods[] = {
    {"scan_block", py_scan_block, METH_VARARGS,
     "scan_block(raw, height, expect_hash=None) -> (code, ...): one block "
     "in, the reveal archive's records out (see nodsig.kernel)."},
    {"fuse_pieces", py_fuse_pieces, METH_VARARGS,
     "fuse_pieces(pieces, rec, dedup_len, rule) -> (blob, dups) or None: "
     "one round of the fusion's k-way stage (see nodsig.kernel)."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_native",
    "The native kernel of the reveal archive's scan (see nodsig.kernel).",
    -1, methods, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__native(void)
{
    return PyModule_Create(&module);
}
