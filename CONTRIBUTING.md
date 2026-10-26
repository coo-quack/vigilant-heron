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
cargo test --workspace --locked                            # Tests
cargo llvm-cov --workspace --locked --fail-under-lines 90  # test job: tests and line coverage
bash scripts/e2e.sh                                        # e2e job
cargo deny --locked check                                  # audit job
cargo machete                                              # deadcode job
pnpm run dup                                               # duplication job
cargo bench --bench hot_path                              # benchmarks (bench job runs them once with -- --test)
docker buildx build --target binaries --platform linux/amd64,linux/arm64 \
  --output type=local,dest=dist .                         # release-build job; then, on Linux:
bash scripts/check-release-binaries.sh dist "$(cargo pkgid | sed 's/.*[#@]//')"
```

`cargo install --locked cargo-deny cargo-machete cargo-llvm-cov` installs the three
tools, and `rustup component add llvm-tools` adds what `cargo llvm-cov` needs.

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
- Line coverage of the tests stays at 90% or more. The `test` job runs the tests
  under `cargo llvm-cov` and fails below that, so new code needs its tests.

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

## Mutation testing

Mutation testing checks whether the tests notice a change in the code. The
tool, cargo-mutants, changes the code one place at a time (for example, it
replaces the body of a function that returns `bool` with `true` or with `false`)
and runs the tests. A test should fail for each change. If every test still
passes, that change is a **missed mutant**, which means a test is missing or
too weak.

`.github/workflows/mutants.yml` runs it every Sunday night (Monday 03:17 JST)
in 32 shards. When the run finds missed mutants, timed-out mutants, or fails,
it opens or updates the issue "Weekly mutation testing: findings". When a later
run is clean, it closes that issue. The full output is in the `mutants-*`
artifacts of the run. The settings are in `.cargo/mutants.toml`.

To run it on one file locally:

```bash
cargo mutants --file src/skip_suggest.rs
```

A full run takes hours, so run it for the file you are changing. Its output is
written to `mutants.out/`, and the lines in `missed.txt` tell you which change
the tests did not catch.

## Benchmarks

`benches/hot_path.rs` measures the request hot path through the public API:
`check_request_with` for four kinds of request (a plain page, a page a skip rule
forwards, a long request that goes through every built-in rule, and a request a
built-in rule blocks) against a configuration loaded once, `suggest_skip_rules`
over 10,000 access log lines, and loading the sample configuration.

Timings on a laptop or a shared runner are noisy, so compare runs on the same
machine. Save a baseline before a change, then compare after it:

```bash
cargo bench --bench hot_path -- --save-baseline before
# make the change
cargo bench --bench hot_path -- --baseline before
```

The `bench` CI job only runs the benchmarks once to check that they build and
run. The `Bench` workflow (`.github/workflows/bench.yml`) runs them every Sunday
at 18:43 UTC and uploads `target/criterion` as the `criterion-<run_id>`
artifact, kept for 90 days, so results can be compared week to week.

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

Branch protection on `develop` and `main` is managed in coo-quack/iac. It
requires these CI jobs to pass before a PR can be merged: `audit`, `lint`, `fmt`,
`test`, `e2e`, `deadcode`, `duplication`, `bench` and `release-build`. Rulesets
add reviews: a change to a path listed in `.github/CODEOWNERS` needs its owner's
approval on both branches, and a PR to `main` needs one approving review.

## Pull Requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`)
- Keep the CI job names (`audit`, `lint`, `fmt`, `test`, `e2e`, `deadcode`,
  `duplication`, `bench`, `release-build`) unchanged: they are the required status checks registered in coo-quack/iac
