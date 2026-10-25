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

## Pull Requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`)
- Keep the CI job names (`audit`, `lint`, `fmt`, `test`, `e2e`, `deadcode`)
  unchanged: they are the required status checks registered in coo-quack/iac
