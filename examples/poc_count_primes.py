"""POC workload: count the prime numbers below LIMIT (a heavy computation of independent tasks).

The AST analysis finds one GO region: the ``for n in range(LIMIT)`` loop. ``n`` is the loop
variable, ``LIMIT`` a read-only constant, ``is_prime`` a function defined in this file that only
reads its argument, and ``count += 1`` a recognized sum accumulator (SRS Table 5.3.1). So the
Master splits the range into sub-ranges (Table 5.3.2), the Worker Nodes pull and count them, and
the Master adds the partial counts.
"""

import math

LIMIT = 3_000_000


def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    return all(n % f for f in range(3, math.isqrt(n) + 1, 2))


count = 0
for n in range(LIMIT):
    if is_prime(n):
        count += 1
print("primes below", LIMIT, ":", count)
