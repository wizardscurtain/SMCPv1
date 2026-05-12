# SMCPv1 — Secure Model Context Protocol (Python reference implementation)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm](https://img.shields.io/npm/v/smcp-security.svg)](https://www.npmjs.com/package/smcp-security)

A Python security middleware for Model Context Protocol (MCP) implementations. Real, working, ~15K LOC at `libraries/python/smcp_security/`. Uses standard primitives (`cryptography`, `PyJWT`, `argon2-cffi`, `pyotp`) — no homemade crypto.

> **2026-05-12 — P0.4 honesty pass.** Earlier versions of this README claimed publication in 7 ecosystems, six-language parity, SOC 2 / ISO 27001 / GDPR / HIPAA / PCI DSS compliance, and 10,000+ req/s throughput. None of those claims survive a direct inspection of the code. This README is now scoped to what actually exists in this repo. The aspirational marketing copy is preserved in git history (commit before this one) for anyone who needs to reference it.

## What's in this repo

| Path | Status | Notes |
|---|---|---|
| `libraries/python/smcp_security/` | **Real** | ~15K LOC. The reference implementation. Real tests, real crypto. The thing you can actually use. |
| `code/` | **Real (duplicate)** | An older copy of the Python implementation. The two have drifted slightly; `libraries/python/` is canonical going forward. Reconciliation is a future task. |
| `experiments/{csharp,go,java,nodejs,rust,vscode-extension}/` | **Incomplete** | Facade ports referencing modules that don't exist. See [`experiments/STATUS.md`](experiments/STATUS.md). Do NOT use. |
| `paper/SMCP_v1_Academic_Paper.md` | **Draft** | Academic paper. ArXiv ID is a placeholder (`2025.XXXXX`); ~12 of 20 references lack DOI/page numbers; perf tables are not reproducible from the code in this repo. Treat as a draft, not a published artifact. |
| `deployment/`, `docs/` | **Partial** | Some real configuration; some scaffolding. Read with skepticism. |

## What's actually published

| Registry | Package | Status |
|---|---|---|
| **npm** | `smcp-security@1.0.0` | **Published.** The tarball is 46 KB and contains compiled JavaScript. Note that this JavaScript is NOT generated from the source in `experiments/nodejs/` — the npm artifact is real but its source-of-truth is not visible in this repo. |
| PyPI | `smcp-security` | **Not published.** The Python library is real and could be published; it isn't yet. |
| crates.io | `smcp-security` | Not published. |
| Maven Central | `com.smcp:smcp-security` | Not published. |
| NuGet | `SMCP.Security` | Not published. |
| VS Code Marketplace | `smcp-security` | Not published. |

If you see badges in older versions of this README linking to those registries, they 404 today.

## Quick start (Python)

```bash
# From a checkout of this repo (PyPI publication TBD):
pip install -e libraries/python
```

```python
from smcp_security import SMCPSecurityFramework

security = SMCPSecurityFramework()
validated_request = security.validate_request(mcp_request)
```

See [`libraries/python/README.md`](libraries/python/README.md) for the full Python API.

## What it actually does

The Python reference implements:

- **Input validation** (`input_validation.py`): schema check, content sanitization (regex-based), injection/path-traversal pattern detection.
- **Authentication** (`authentication.py`): JWT via `PyJWT`. MFA via `pyotp`. Password hashing via `argon2-cffi`. No homemade crypto.
- **Authorization** (`authorization.py`): role-based access control (RBAC) with hierarchical permission resolution.
- **Rate limiting** (`rate_limiting.py`): in-memory token bucket. Per-user / per-IP. Configurable thresholds.
- **AI Immune System** (`ai_immune.py`): `sklearn.IsolationForest` over 15 hand-engineered features, with a regex fallback. **Not BERT-based, not transformer-based, not deep learning.** Earlier README copy implied otherwise — it didn't. Treat as a structured anomaly heuristic, not "AI-immune."
- **Cryptography utilities** (`cryptography.py`): AES-256-GCM wrappers via `cryptography`. **Important:** `_process_cryptography()` is a no-op in the request pipeline today. The wrappers exist; the pipeline does not call them. If you need end-to-end encryption, you'd need to wire it in yourself.
- **Audit logging** (`audit.py`): structured JSON logging of security events.

## What it does NOT do (despite earlier README claims)

- **Sub-millisecond overhead.** Tests assert `< 50 ms` mean. The earlier "<1 ms" claim is unsubstantiated.
- **10,000+ req/s throughput.** Not asserted anywhere in the test suite.
- **SOC 2 Type II / ISO 27001 / GDPR / HIPAA / PCI DSS compliance.** No code, audit, or attestation in this repo backs these claims.
- **End-to-end encryption** in the request pipeline. The cryptography primitives exist; the pipeline doesn't use them.
- **Adaptive DoS protection.** `_process_dos_protection()` is similarly implemented but not wired into the request flow.
- **Cross-language parity.** Only Python is real; see [`experiments/STATUS.md`](experiments/STATUS.md).

## Architecture

```
MCP Request
   │
   ▼
┌─────────────────────────────┐
│   Input Validation Layer    │  ← regex + schema (real)
├─────────────────────────────┤
│   AI Immune (IsolationForest)│ ← real, but a structured heuristic, not deep learning
├─────────────────────────────┤
│   Rate Limiting             │  ← in-memory token bucket (real)
├─────────────────────────────┤
│   Authentication (JWT/MFA)  │  ← real, standard primitives
├─────────────────────────────┤
│   Authorization (RBAC)      │  ← real, hierarchical
├─────────────────────────────┤
│   (Cryptography — wrappers  │  ← exists, but NOT called by the pipeline
│    exist, pipeline no-op)   │     wire it in yourself if you need it
├─────────────────────────────┤
│   Audit Logging             │  ← real, JSON-structured
└─────────────────────────────┘
   │
   ▼
MCP Response
```

## Tests

```bash
cd libraries/python
python -m pytest tests/ -v
```

Roughly 9,000 LOC of tests across unit + integration + fixtures. Real coverage of the components described above. The only enforced performance threshold is `< 50 ms` mean per request — not the README's older "<1 ms" claim.

## What this repo is good for

- A reference Python middleware that you can read, fork, and extend.
- A starting point for SMCP-style request validation in MCP server implementations.
- A working example of using `cryptography` / `PyJWT` / `argon2-cffi` / `pyotp` correctly in a security pipeline.

## What this repo is NOT good for (yet)

- A drop-in production security framework you can claim compliance for. Not without your own attestation work.
- A cross-language framework. Use only the Python implementation.
- A research artifact. The paper is a draft. The arXiv ID is a placeholder. The performance tables in the paper are not reproducible from this repo.

## Roadmap (honest)

The smallest credible next step is:

1. Wire `_process_cryptography` and `_process_dos_protection` into the request pipeline so the README's E2EE and adaptive-DoS claims become true.
2. Publish the Python library to PyPI under the right namespace.
3. Pick **one** language port (Rust looks closest to viable) and finish it end-to-end before claiming multi-language support.
4. Either finish the academic paper to actual submission quality (replace placeholder arXiv ID, fill in references, run the benchmarks that produce the perf tables) or move it to `docs/draft-paper/` and stop linking to it as if it were a published artifact.
5. Either substantiate the compliance claims (SOC 2 audit, ISO attestation, HIPAA BAA template, PCI DSS scope statement) or drop them entirely.

## License

[MIT License](LICENSE).

## Acknowledgments

- [Model Context Protocol](https://github.com/modelcontextprotocol) team for the foundational protocol.
- The maintainers of `cryptography`, `PyJWT`, `argon2-cffi`, `pyotp`, and `scikit-learn`.

---

*Last updated: 2026-05-12 (P0.4 honesty pass per the Serendipity Labs merge plan).*
