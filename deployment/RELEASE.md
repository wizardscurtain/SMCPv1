# Release & Publishing Guide 🚀

This document explains how to publish the SMCP libraries and how the GitHub Actions workflows we added work.

## Workflows added

- `.github/workflows/python-ci.yml` — CI for Python: runs linting, mypy, and tests for Python 3.11 & 3.12 on push/PR to `main`.
- `.github/workflows/publish-python.yml` — Publishes the Python package to PyPI when a Git tag `v*` is pushed or via manual dispatch.
- `.github/workflows/publish-all.yml` — Manual workflow to run `scripts/publish-all.sh` with inputs to select libraries, run dry-run, or skip tests.

## Required repository secrets

Set these in the repository Settings → Secrets and Variables → Actions:

- `PYPI_API_TOKEN` — PyPI API token (set as `TWINE_PASSWORD`; `TWINE_USERNAME` is `__token__`).
- `NPM_TOKEN` — npm auth token for publishing to npm (used to write `~/.npmrc` in the workflow).
- `CRATES_IO_TOKEN` — Token for crates.io if you publish Rust crates from CI.
- `TEST_PYPI_API_TOKEN` — (optional) Token for TestPyPI used by `.github/workflows/publish-python-testpypi.yml`.
- `GITHUB_TOKEN` — provided by Actions automatically; used by some scripts.

For other registries (Maven Central, NuGet) please follow each language's publish script and add the appropriate secrets (e.g., `MAVEN_USERNAME`, `MAVEN_PASSWORD`, `NUGET_API_KEY`).

## How to publish

Python (recommended flow):

1. Create a Git tag for the release e.g. `git tag v1.2.3` and push it: `git push origin v1.2.3`.
2. The `publish-python` workflow will run automatically and publish to PyPI using `PYPI_API_TOKEN`.

Bulk publish (manual):

1. Open the Actions tab and trigger the `Publish All Libraries (manual)` workflow.
2. Pass `libraries` (comma-separated) or `all`. The default run is `dry_run=true` — inspect logs first and then set `dry_run=false` for real publishing.

## Notes & Recommendations

- The Python packaging config is in `libraries/python/pyproject.toml` (the publish script uses this folder). The project also contains `code/pyproject.toml` which is the development package — we keep both to support CI and packaging.
- CI runs tests using the configuration in `code/pytest.ini`.
- The `Automated Release` workflow (`.github/workflows/release.yml`) runs automatically on pushes to `main` (for example, after merging a PR). It runs tests, uses Commitizen to determine the version bump from conventional commits, updates version and changelog, creates tags and a draft GitHub Release, and then publishes the Python package to PyPI if `PYPI_API_TOKEN` is present. For manual runs you can still use `workflow_dispatch` and pass `bump` to override the automatic determination.
- Add repository-level `CODEOWNERS` to ensure required reviewers and approvals for release PRs. Replace the placeholder owners with org/team names as appropriate.
- Enable Dependabot (`.github/dependabot.yml`) to keep dependencies up to date and to surface security updates automatically. Set dependabot schedule and add necessary registry credentials in repository settings if you use private registries.
- Protect the `main` branch (see `deployment/BRANCH_PROTECTION.md`) and require CI / reviews before merging. This ensures releases created by the automated release flow come from a validated and reviewed state. (Branch protection has been configured to require status checks, code owner reviews, and to disable force pushes.)
- We added a `publish to TestPyPI` workflow (`.github/workflows/publish-python-testpypi.yml`) which uploads releases with the `v*-rc*` tag pattern to TestPyPI for validation before production publishing.

## Troubleshooting

- If twine complains about authentication, ensure `TWINE_USERNAME` is set to `__token__` and `TWINE_PASSWORD` is `PYPI_API_TOKEN`.
- For npm, make sure `NPM_TOKEN` has publish permissions and the account has access to the package name `smcp-security`.
- For crates.io, make sure the token is configured and cargo is logged in on CI (the publish script will rely on token availability).

If you want, I can add more automation such as a `release` workflow using Commitizen, automatic changelog generation, or per-language CI jobs. Let me know which priorities you want next (✅ PyPI release automation, ✅ multi-language CI, ✅ automatic changelog & releases).
