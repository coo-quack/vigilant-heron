# Contributing

## Development Setup

```bash
git clone https://github.com/coo-quack/vigilant-heron.git
cd vigilant-heron
cargo build
```

`rust-toolchain.toml` pins the toolchain; rustup installs it on the first
`cargo` call. The e2e suite needs Docker with Compose.

## Commands

```bash
cargo fmt --all                                            # Format
cargo fmt --all -- --check                                 # fmt job
cargo clippy --workspace --all-targets --locked -- -D warnings  # lint job
RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked  # lint job
cargo test --workspace --locked                            # test job
bash scripts/e2e.sh                                        # e2e job
cargo deny --locked check                                  # audit job
cargo machete                                              # deadcode job
pnpm run dup                                               # duplication job
```

`cargo install --locked cargo-deny cargo-machete` installs the two tools.

## Rules the CI enforces

- Lints live in `[workspace.lints]` in `Cargo.toml`. They are not to be
  weakened. `unsafe` code is forbidden, and code outside tests may not
  `unwrap`, `expect`, `panic!`, index or slice by position: the router parses
  attacker-controlled input, so every failure has to be a handled `Result`.
- A lint that must be silenced uses `#[expect(lint, reason = "...")]`, never
  `#[allow]`.
- Dead code: items that are not part of the public API are `pub(crate)` (the
  `unreachable_pub` lint), so `dead_code` rejects the unused ones. Unused
  dependencies are caught by `cargo machete`.
- Every public item has a doc comment; fallible functions document their
  errors under `# Errors`.
- Duplicated code in `src/` may not grow beyond the `threshold` in
  `.jscpd.json`. List the clones with `pnpm run dup`.
- Comments and documentation are written in English.

## Tests

- Unit tests sit next to the code in `#[cfg(test)]` modules. Test names read
  as sentences and check one behavior each; tables use `rstest`, properties
  `proptest`.
- `tests/router.rs` runs the router in-process against a stub upstream and a
  stub decision backend.
- `tests/e2e.rs` runs against the Compose stack in `e2e/` (nginx in front, the
  router image, the stub decider, an upstream). Its tests are `#[ignore]`d in
  the normal run; `scripts/e2e.sh` starts the stack and runs them.
- Expected values are never changed to match what the code happens to do.

## Branching Strategy

```
main
 ├── develop          ← integration branch
 │    └── <type>/*   ← everything that is not an urgent production fix
 └── hotfix/*        ← urgent production fixes
```

1. Branch from `develop`: `git checkout -b feat/your-change develop`
2. Open a PR targeting `develop`
3. After CI passes, merge into `develop`
4. When ready to release, open a PR from `develop` → `main`

## Hotfix

1. Branch from `main`: `git checkout -b hotfix/your-fix main`
2. Open a PR targeting `main`, add a `## vX.Y.Z (YYYY-MM-DD)` section to
   `CHANGELOG.md` and bump `version` in `Cargo.toml`
3. After merging into `main`, `release.yml` publishes the image and creates the
   tag and release
4. `backport.yml` then opens a PR that merges `main` into `develop`. It is
   merged by hand once CI passes, so `develop` gets the fix

## Release Checklist

When bumping a version, open a PR from `develop` → `main` with:

1. Update `version` in `Cargo.toml`
2. Add a `## vX.Y.Z (YYYY-MM-DD)` section to `CHANGELOG.md`
   - `release.yml` extracts that section as the GitHub Release notes, so the
     heading must start with `## vX.Y.Z`
3. Review `README.md` and `examples/vigilant-heron.conf` for changed directives or behavior

After merging into `main`, `release.yml` automatically:

- Runs the tests (`cargo test --workspace --locked`) and the advisory check
  (`cargo deny` and `pnpm audit`, the same steps as the `audit` CI job) in the
  `verify` job, which has read-only access and keeps no credential in its
  checkout
- Builds and pushes `ghcr.io/coo-quack/vigilant-heron:latest` and
  `:X.Y.Z` for `linux/amd64` and `linux/arm64` in the `publish` job, which runs
  only after `verify` passes
- Builds the Linux binaries for x86_64 and aarch64 from the same build as the
  image, checks that each needs glibc 2.39 or older and that the x86_64 binary
  reports the version, and packages them with `SHA256SUMS`
- Creates the git tag `vX.Y.Z` through the GitHub REST API
- Creates a GitHub Release with the notes from `CHANGELOG.md` and the binaries
  attached

The `publish` job does not run the project's tests or its advisory check, and its
checkout keeps no credential, so the write token is not left in `.git/config`.

To check the multi-arch build without publishing, run the `Release` workflow by
hand from `develop` (`dry_run` is `true` by default). It runs `verify`, builds
both platforms, checks the binaries, and pushes, tags and releases nothing.

`backport.yml` opens the `main` → `develop` sync PR after every merge into
`main`; see the hotfix steps above.

## Repository Rules

While the repository is private on the GitHub Free plan, branch protection,
rulesets and auto-merge are not available. So CI must be checked by hand: every
PR is merged only after all its checks are green, and no PR is merged with a
failing or missing check.

The job names in the CI workflow (`audit`, `lint`, `fmt`, `test`, `e2e`,
`deadcode`) stay registered in coo-quack/iac, so they keep working when the
repository goes public and rulesets can require them.

## Pull Requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`)
- Keep the CI job names (`audit`, `lint`, `fmt`, `test`, `e2e`, `deadcode`)
  unchanged: they are the required status checks registered in coo-quack/iac
