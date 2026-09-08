#!/usr/bin/env python3
"""
progress.py — the pace of a long pass, measured one way.

Three scan loops carried the same four variables and the same
arithmetic, with a comment in each pointing at the other for the
rationale. The rationale, once: two rates, and the ETA from the last
interval. The stretch average restarts from zero at every resume and,
on a chain whose per-block cost only grows, an average seeded by light
blocks stays permanently above the true pace: two stretches of
different length printing one "blk/s" are not comparable. The last
checkpoint interval is what "now" means. The ETA extrapolates at
constant per-block cost, which on this chain is optimistic by
construction; the tag says so rather than letting the number claim
more than it checked.

A kernel: no I/O, no flag, no knowledge of what is being counted.
"""

import time


class Pace:
    """Count units done since this pass started, and report the rate
    of the last interval, the average, and the ETA to `end`."""

    def __init__(self, end, unit="blk"):
        self.end = end
        self.unit = unit
        self.started = time.monotonic()
        self.done = 0
        self.mark_t = self.started
        self.mark_done = 0

    def add(self, n=1):
        self.done += n

    def rates(self, at):
        """(rate of the last interval, average rate, hours left), and
        the interval starts anew here."""
        now = time.monotonic()
        step = ((self.done - self.mark_done) / (now - self.mark_t)
                if now > self.mark_t else 0.0)
        avg = self.done / (now - self.started) if now > self.started else 0.0
        self.mark_t, self.mark_done = now, self.done
        eta_h = (self.end - at) / step / 3600 if step else 0.0
        return step, avg, eta_h

    def text(self, at):
        """The one sentence every scan prints at a checkpoint."""
        step, avg, eta_h = self.rates(at)
        return (f"{step:.1f} {self.unit}/s now, {avg:.1f} avg, "
                f"~{eta_h:.1f} h left (flat-cost extrapolation)")
