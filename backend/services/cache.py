"""Bounded TTL/LRU with isolated values and thread-safe statistics."""
import copy
import time
from collections import OrderedDict
from threading import RLock


class TTLCache:
    def __init__(self, maxsize=512, ttl=86400, clock=time.monotonic):
        self.maxsize, self.ttl, self.clock = maxsize, ttl, clock
        self.entries = OrderedDict()
        self.lock = RLock()
        self.hits = self.misses = self.evictions = 0

    def _expire(self):
        now = self.clock()
        for key in [k for k, (deadline, _) in self.entries.items() if deadline <= now]:
            del self.entries[key]

    def get(self, key):
        with self.lock:
            self._expire()
            if key not in self.entries:
                self.misses += 1
                return None
            self.hits += 1
            self.entries.move_to_end(key)
            return copy.deepcopy(self.entries[key][1])

    def put(self, key, value):
        with self.lock:
            self._expire()
            self.entries[key] = (self.clock() + self.ttl, copy.deepcopy(value))
            self.entries.move_to_end(key)
            while len(self.entries) > self.maxsize:
                self.entries.popitem(last=False)
                self.evictions += 1

    def stats(self):
        with self.lock:
            self._expire()
            return {'size': len(self.entries), 'maxsize': self.maxsize, 'ttl_seconds': self.ttl,
                    'hits': self.hits, 'misses': self.misses, 'evictions': self.evictions}
