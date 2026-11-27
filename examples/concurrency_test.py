"""Test program: mutex (Lock / RLock), sort, semaphore, threads and processes.

Expected result in the Cluster Computing system (SRS Table 3.3.1, Section 5.3.2):
  * security screening: SAFE - threads and processes are not security violations (Table 3.2.1);
  * AST analysis: NOT ELIGIBLE (check P1) - a Semaphore, an RLock that guards more than one
    accumulator update, and multiprocessing make the whole program not eligible, because
    concurrent code left on the Master would make the output non-deterministic;
  * the program is therefore not executed (SRS 3.2), and every reason is listed on the dashboard.

See concurrency_go.py for the same workload without the unsupported constructs: it runs in
standard and in cluster mode.
"""

import hashlib
import multiprocessing
import threading


def stretch(word, rounds=3000):
    """CPU-bound key stretching: iterated SHA-256."""
    h = word
    for _ in range(rounds):
        h = hashlib.sha256(h.encode()).hexdigest()
    return h


# 1. threads + mutex: a Lock protects the shared result list
digests = []
lock = threading.Lock()


def hash_part(part):
    for w in part:
        d = stretch(w)
        with lock:
            digests.append(d[:16])


words = [f"user{i:04d}" for i in range(400)]
parts = [words[i::4] for i in range(4)]
threads = [threading.Thread(target=hash_part, args=(p,)) for p in parts]
for t in threads:
    t.start()
for t in threads:
    t.join()

# 2. semaphore: at most two threads inside the critical section; RLock re-entered
gate = threading.BoundedSemaphore(2)
rlock = threading.RLock()
visits = []


def visit(i):
    with gate:
        with rlock:
            with rlock:
                visits.append(i * i)


visitors = [threading.Thread(target=visit, args=(i,)) for i in range(8)]
for t in visitors:
    t.start()
for t in visitors:
    t.join()


# 3. processes: a multiprocessing pool
def cube(x):
    return x * x * x


if __name__ == "__main__":
    with multiprocessing.Pool(2) as pool:
        cubes = pool.map(cube, range(20))

    # 4. sort
    ordered = sorted(digests)
    print(len(ordered), ordered[0], ordered[-1])
    print(sorted(visits))
    print(sum(cubes))
