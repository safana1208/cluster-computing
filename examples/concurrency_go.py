"""Companion test program: mutex, sort and threads in the patterns the SRS supports (Section 5.3.2).

Expected result: SAFE, ELIGIBLE - three GO regions:
  #1 thread group (Pattern A: Thread(target=...) started and joined, a Lock that only protects
     the accumulator update) -> one task per thread;
  #2 for loop with a sum accumulator -> sub-ranges of indices;
  #3 sorted(...) -> two-phase sort (Worker Nodes sort chunks, the Master merges them).
In standard mode the threads share the GIL, so they run one after another; in cluster mode every
thread becomes a task on a different Worker Node.
"""

import hashlib
import threading


def stretch(word, rounds=3000):
    h = word
    for _ in range(rounds):
        h = hashlib.sha256(h.encode()).hexdigest()
    return h


digests = []
lock = threading.Lock()


def hash_part(part):
    for w in part:
        d = stretch(w)
        with lock:
            digests.append(d[:16])


words = [f"user{i:04d}" for i in range(800)]
parts = [words[i::8] for i in range(8)]
threads = [threading.Thread(target=hash_part, args=(p,)) for p in parts]
for t in threads:
    t.start()
for t in threads:
    t.join()

checksum = 0
for i in range(200000):
    checksum += int(stretch(str(i), 4)[:6], 16) % 97

ordered = sorted(digests)
print(len(ordered), ordered[0], ordered[-1])
print(checksum)
