# Action Items & Recommendations ✅

This is a prioritized list of work to fully prepare the repository for organization-wide distribution across languages and registries.

1. CI and Tests
   - [x] Add Python CI (`.github/workflows/python-ci.yml`).
   - [x] Add per-language CI jobs (node, java/maven, go, rust, csharp, vscode) that run unit tests and linters.
   - [ ] Enable cross-OS testing where relevant (Linux, macOS, Windows) for languages like .NET and Node.

2. Release Automation
   - [x] Add PyPI publish workflow (`.github/workflows/publish-python.yml`).
   - [x] Add manual `publish-all` workflow to orchestrate multi-language publishing.
   - [ ] Add automatic semantic-release flow: use Commitizen + GitHub Actions to bump versions, build, tag, and create releases automatically from PR merges using conventional commits.
   - [ ] Add a workflow to publish to Test PyPI for pre-release validations.

3. Security & Compliance
   - [x] Add Dependabot for dependency updates (GH Dependabot config).
   - [ ] Add secret scanning and rotate tokens as needed.
   - [ ] Add SLSA provenance generation for release artifacts (where supported).

4. Packaging & Metadata
   - [ ] Decide canonical Python packaging source (currently `libraries/python` vs `code/`). Consolidate to avoid duplication.
   - [ ] Ensure all packages include license, readme, and correct trove classifiers.
   - [ ] Add signed releases if required by downstream organizations.

5. Documentation & Onboarding
   - [x] Add `deployment/RELEASE.md` describing the new workflows and secrets.
   - [x] Add `CODEOWNERS` + protected branches and required status checks (CI, review approvals).
   - [ ] Add per-language publishing notes to `deployment/RELEASE.md` or `docs/`.

6. Registry-specific tasks
   - [ ] npm: Ensure package name ownership and set `NPM_TOKEN` in repo secrets.
   - [ ] Maven Central: Configure Sonatype credentials and GPG signing, add `MAVEN_*` secrets.
   - [ ] NuGet: Configure API key and set `NUGET_API_KEY` secret.
   - [ ] crates.io: Ensure crate naming and `CRATES_IO_TOKEN` is set.

7. CI Observability
   - [ ] Add code coverage publishing (Codecov/coveralls) integration.
   - [ ] Add test reporting (JUnit) parsing and annotations using GitHub Checks.

If you'd like, I can start implementing items from the top of the list next. Pick one: add per-language CI, add automatic release with Commitizen, or add Dependabot and secret scanning. Which should I prioritize?
