"""Sliding time-window state. Rules evaluate over multiple horizons at once,
so a fast scan trips the 60s window and a slow one trips the 1hr window.

Holds recent flows in memory, indexed by time, and serves any window on demand."""
import time
from collections import deque

# Horizons every rule can query, in seconds
WINDOWS = {"short": 60, "medium": 300, "long": 3600}
MAX_AGE = max(WINDOWS.values())


class SlidingWindow:
    def __init__(self):
        self.flows = deque()  # (bucket_ts, flow_dict), oldest first

    def add_flows(self, flow_rows):
        """Append a batch of flushed flow rows."""
        for f in flow_rows:
            self.flows.append((f["bucket_ts"], f))
        self._evict()

    def _evict(self):
        cutoff = time.time() - MAX_AGE
        while self.flows and self.flows[0][0] < cutoff:
            self.flows.popleft()

    def get(self, horizon):
        """Return flows within the named window ('short'/'medium'/'long')."""
        span = WINDOWS[horizon]
        cutoff = time.time() - span
        return [f for ts, f in self.flows if ts >= cutoff]

    def stats(self):
        return {"buffered_flows": len(self.flows),
                "oldest_age": time.time() - self.flows[0][0] if self.flows else 0}
