"""
tests/fixtures/leaky_python/all_bugs.py
-----------------------------------------
Intentionally memory-leaky Python program.
Run with: python -m memray run -o out.bin all_bugs.py
        or: python all_bugs.py
"""

import gc
import sys
import weakref


# ── 1. Reference cycle preventing collection ─────────────────────────────────
class Node:
    def __init__(self, val):
        self.val  = val
        self.next = None
        self.prev = None   # doubly-linked → cycle


def make_cycle():
    a = Node(1)
    b = Node(2)
    a.next = b
    b.prev = a   # cycle: a → b → a
    # When a and b go out of scope the cycle keeps them alive
    # until gc.collect() — but gc may never run in short-lived scripts
    return None   # drop references — cycle lives on


# ── 2. Global cache that grows without bound ──────────────────────────────────
_UNBOUNDED_CACHE: dict = {}

def cache_everything(key, value):
    """Classic 'memoize but never evict' pattern."""
    _UNBOUNDED_CACHE[key] = value


def fill_cache(n: int = 100_000):
    for i in range(n):
        cache_everything(f"key_{i}", b"x" * 1024)   # 1KB per entry → 100MB


# ── 3. Closure capturing large object ─────────────────────────────────────────
def closure_leak():
    big_data = bytearray(10 * 1024 * 1024)   # 10 MB

    def callback():
        return len(big_data)    # captures big_data

    # Registering callback somewhere global → big_data never freed
    _UNBOUNDED_CACHE["callback"] = callback


# ── 4. __del__ that prevents cycle collection ─────────────────────────────────
class WithDel:
    def __init__(self, name):
        self.name = name
        self.ref  = None   # set externally to form a cycle

    def __del__(self):
        # CPython < 3.4: objects with __del__ in a cycle go to gc.garbage
        # Modern CPython handles it but __del__ still complicates things
        pass


def del_cycle():
    a = WithDel("a")
    b = WithDel("b")
    a.ref = b
    b.ref = a   # cycle with __del__


# ── 5. Event listener accumulation ────────────────────────────────────────────
class EventEmitter:
    _listeners: list = []

    @classmethod
    def on(cls, fn):
        cls._listeners.append(fn)   # strong ref — listeners never removed

    @classmethod
    def emit(cls):
        for fn in cls._listeners:
            fn()


def register_many_listeners(n: int = 1000):
    for i in range(n):
        data = bytearray(4096)   # 4KB captured per listener

        def listener(d=data):
            return len(d)

        EventEmitter.on(listener)


# ── 6. Generator not exhausted ────────────────────────────────────────────────
def large_generator():
    for i in range(10_000_000):
        yield bytearray(100)


def leak_generator():
    gen = large_generator()
    first = next(gen)
    # gen is never exhausted or closed — holds frame alive
    _UNBOUNDED_CACHE["gen"] = gen


# ── 7. Interned large strings ─────────────────────────────────────────────────
_STRING_POOL: list = []

def intern_strings(n: int = 10_000):
    for i in range(n):
        s = f"very_long_unique_string_{i}_" + "x" * 256
        _STRING_POOL.append(s)   # never removed


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    which = int(sys.argv[1]) if len(sys.argv) > 1 else 0

    if which == 1 or which == 0:
        print("1. Making reference cycles...")
        for _ in range(1000):
            make_cycle()

    if which == 2 or which == 0:
        print("2. Filling unbounded cache...")
        fill_cache(10_000)

    if which == 3 or which == 0:
        print("3. Closure capturing large object...")
        closure_leak()

    if which == 4 or which == 0:
        print("4. Cycles with __del__...")
        for _ in range(500):
            del_cycle()

    if which == 5 or which == 0:
        print("5. Accumulating event listeners...")
        register_many_listeners(200)

    if which == 6 or which == 0:
        print("6. Leaking generator...")
        leak_generator()

    if which == 7 or which == 0:
        print("7. Interning large strings...")
        intern_strings(2000)

    # Show gc stats
    gc.collect()
    print(f"\nGC garbage count: {len(gc.garbage)}")
    print(f"Cache size: {len(_UNBOUNDED_CACHE)} entries")
    print(f"Listeners: {len(EventEmitter._listeners)}")
    print(f"String pool: {len(_STRING_POOL)}")
