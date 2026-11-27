"""Merge sort on the cluster: the algorithm of thread_merge_sort.py, written in a pattern the SRS distributes.

What changed compared with thread_merge_sort.py, and why (SRS 5.3.2, 5.4.2):
  * The worker is a module-level function, not a closure, so it can be shipped to a Worker Node.
  * No Semaphore: on the cluster the number of Worker Nodes limits concurrency, not the program.
  * No shared objects mutated by the threads (SortMetrics / TaskTracker): Worker Nodes do not share memory.
    Each thread returns its result, and the only shared update is one list append under a Lock - a
    recognized accumulator, rebuilt by the Master in submission order.
  * merge_sort() stays recursive: recursion inside one task runs locally on one Worker Node.

Standard run: 8 threads in one process (the GIL lets only one sort run at a time).
Cluster run:  every submit() becomes a task on a Worker Node, so the sorts really run in parallel.
"""

import random
import threading
from concurrent.futures import ThreadPoolExecutor


def merge_sort(items):
    """Return a new, stably sorted list (recursive merge sort; the input is not modified)."""
    data = list(items)
    if len(data) <= 1:
        return data
    mid = len(data) // 2
    return _merge(merge_sort(data[:mid]), merge_sort(data[mid:]))


def _merge(left, right):
    merged = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:  # "<=" takes from the left on ties: stable
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
    merged.extend(left[i:])
    merged.extend(right[j:])
    return merged


sizes = []
lock = threading.Lock()


def sort_batch(batch):
    result = merge_sort(batch)
    with lock:  # mutex around a single accumulator update
        sizes.append(len(batch))
    return result


rng = random.Random(42)
batches = [[rng.randint(0, 1_000_000) for _ in range(rng.randint(15_000, 25_000))] for _ in range(48)]

with ThreadPoolExecutor(max_workers=8) as pool:
    futures = [pool.submit(sort_batch, b) for b in batches]
    sorted_batches = [f.result() for f in futures]

ok = all(s == sorted(b) for s, b in zip(sorted_batches, batches))
print(f"merge_sort of {len(batches)} lists: {'all correct' if ok else 'MISMATCH'}")
print(f"lists sorted: {len(sizes)}, elements sorted: {sum(sizes)}")
print("first list head:", sorted_batches[0][:5])
