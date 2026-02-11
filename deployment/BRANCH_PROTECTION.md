# Branch Protection Recommendations

To ensure safe, auditable, and reproducible releases, configure branch protections for `main` with the following recommendations:

- Require pull request reviews before merging (1-2 approving reviews).
- Require status checks to pass before merging, including:
  - `CI - Python` (python-ci)
  - `CI - Node.js` (nodejs-ci)
  - `CI - Java (Maven)` (java-ci)
  - `CI - Go` (go-ci)
  - `CI - Rust` (rust-ci)
  - `CI - .NET` (dotnet-ci)
  - `CI - VS Code Extension` (vscode-ci)
  - `Automated Release` (release.yml) should not be required to prevent release loops, but ensure tests pass on PRs.
- Require signed commits if your organization enforces commit signing.
- Enable branch protection to prevent force-pushes and deletions.
- Optionally require linear history and restrict who can push to the `main` branch.

How to set these:
- GitHub UI: Settings → Branches → Add rule → select `main` and configure the settings above.
- As code: Use GitHub's API or a repository governance tool (Terraform GitHub provider, GitHub CLI with repo settings, or policy-as-code tooling).

Notes:
- Add `CODEOWNERS` to ensure the right people or teams are requested for review on critical changes.
- Ensure Dependabot PRs are included in required status checks as applicable.

If you'd like, I can prepare Terraform or GitHub CLI commands to apply these rules automatically; tell me which method you'd like to use.
