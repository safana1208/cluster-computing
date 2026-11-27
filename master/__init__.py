"""Master Node of the Cluster Computing system.

Receives Python programs, screens them for supply-chain attacks (SRS SAST policy + AST Master +
AI models) inside an isolated Docker sandbox, decides whether they are eligible for parallel and
distributed execution on the cluster, and routes them accordingly. Hosts the operator dashboard.

Kept import-light on purpose: the inspection sandbox and the pre-check worker processes import
``master.eligibility`` / ``master.precheck`` without pulling in the web stack.
"""

__version__ = "1.0.0"
