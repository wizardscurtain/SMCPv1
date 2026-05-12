# Experiments — Multi-Language SMCP Ports (NOT PRODUCTION)

The directories under `experiments/` are **incomplete language ports** of the SMCP security framework. They were previously under `libraries/` with READMEs implying they were production-ready. They are not.

This file documents what's actually in each port as of 2026-05-12 (the P0.4 honesty pass) so anyone — including future-Cecil — knows which artifacts to trust and which to treat as scaffolding.

## What's real

Only the **Python** implementation at `libraries/python/smcp_security/` is a complete, working port. ~15K LOC, real tests, real crypto primitives via `cryptography` / `argon2-cffi` / `PyJWT` / `pyotp`. That's the one you should reference if you want to know what SMCP "does."

## What's in experiments/

Each subdirectory has the same shape: a facade file (or two) that defines a class with the right public method names (`SMCPSecurityFramework.validate_request(...)`, etc.) and references 8–15 supporting classes or modules. **Those supporting classes and modules do not exist in the directory.** The facade file alone won't compile or run.

| Language | LOC | Build/package files present | Compiles standalone? | Notes |
|---|---:|---|---|---|
| `csharp/` | 482 | None | No | Single `.cs` facade. References classes that don't exist in the repo. |
| `go/` | 557 | None | No | Single `.go` facade. Module declaration but no `go.mod`, no supporting packages. |
| `java/` | 424 | None | No | Single `.java` facade under Maven-style directory tree, no `pom.xml`. |
| `nodejs/` | 886 | `package.json`-shaped artifacts | No | **The published npm tarball `smcp-security@1.0.0` does contain compiled JS** for code that is not visible in this repo. The TypeScript source in `experiments/nodejs/` is a facade referencing modules that don't compile. If you need the JS, take it from the npm artifact, not from this directory. |
| `rust/` | 1127 | None | No | More substantial than the others, but supporting modules missing. |
| `vscode-extension/` | 459 | None | No | Extension scaffolding that imports the nodejs facade. |

## What this means for downstream consumers

- **Do not link to these directories** from external docs, papers, or marketing materials as if they were usable libraries.
- **Do not claim publication on PyPI / crates.io / Maven Central / NuGet / VS Marketplace** unless you can `curl` the registry and see the package. As of P0.4, only `npm i smcp-security@1.0.0` actually resolves.
- **Do not** treat the facade method signatures here as a stable cross-language API contract. They're best-effort sketches.

## How this happened

These language ports were generated alongside the Python reference implementation as part of an Emergent.sh-driven multi-language scaffolding pass. The Python port was completed end-to-end; the others were facades intended to be filled in later. The README was updated at the time to claim all six languages were "production-ready" before the supporting code was written. The npm package was the only one actually published.

## What's next

Either:

- **(a)** Delete these directories entirely. The history is preserved in git. **My recommendation if no near-term plan exists to complete any of the ports.**
- **(b)** Pick one port (Rust looks closest to viable), genuinely complete it, run it through the same test suite the Python reference passes, publish the artifact, then move that one directory back under `libraries/` and update the README to list both Python and the chosen second language.

The current state — six unfinished facades under `experiments/` with this STATUS file — is honest and stable. Don't promote anything to `libraries/` without finishing it first.

— *P0.4 honesty pass, 2026-05-12.*
