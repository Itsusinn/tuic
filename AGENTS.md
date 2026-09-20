# Repository Guide for Agents

## Scope and instruction precedence

This file applies to the `tuic/` repository. More specific `AGENTS.md` or `CLAUDE.md` files override it within their subtrees. When working under the `crates/wind/` submodule, follow that repository's own instructions. Before starting a task, read the relevant `README.md`, `LLM.md`, crate manifests, and tests.

`tuic/` is an independent Git repository and Cargo workspace. Run Git, Cargo, and validation commands from this directory unless a command explicitly targets the `crates/wind/` submodule.

## Project overview

TUIC is a low-latency QUIC proxy implementation with standalone server and client applications plus end-to-end tests. The workspace uses Rust edition 2024 and requires Rust 1.85.0 or newer.

| Path | Responsibility |
| --- | --- |
| `crates/tuic-server/` | TUIC server, TLS/ACME, ACL and Clash rules, outbounds, masquerade, and the RESTful management API |
| `crates/tuic-client/` | TUIC client, local SOCKS5, TCP/UDP forwarding, and upstream proxy support |
| `crates/tuic-tests/` | Cross-client/server protocol, reconnect, 0-RTT, UDP fragmentation, masquerade, and shutdown integration tests |
| `crates/wind/` | Independent Git submodule containing the shared proxy framework and TUIC/QUIC implementation; not a member of the root workspace |
| `.github/` | Build targets, container configuration, and release workflows |

The root `Cargo.toml` excludes Wind with `exclude = ["crates/wind"]`, while all three root crates consume Wind crates through path dependencies. Do not treat the root workspace and the Wind workspace as one Cargo workspace.

## Before making changes

1. Run `git status --short`. Preserve unrelated changes and never clean or reset the user's worktree.
2. Determine whether the change belongs in the TUIC application layer or the shared Wind implementation. Protocol encoding, generic QUIC backends, and shared routing, DNS, or ACL behavior usually belong in the top-level `../wind/` repository, not in the `tuic/crates/wind/` submodule checkout.
3. Search for existing migrations, compatibility aliases, test fixtures, and helpers before adding another implementation.
4. On a fresh clone, run `git submodule update --init --recursive` only when the task requires Wind sources.

## Essential commands

```console
# Build the binaries
cargo build --package tuic-server --package tuic-client
cargo build --release --package tuic-server --package tuic-client

# Run a binary; the workspace contains multiple binaries, so name the package
cargo run --package tuic-server -- -c ./config.toml
cargo run --package tuic-client -- -c ./config.toml

# Start with the narrowest relevant test
cargo test --package tuic-server <test-name>
cargo test --package tuic-client <test-name>
cargo test --package tuic-tests --test <integration-test-name>

# Repository-level validation
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

`rustfmt.toml` uses nightly-only options and hard tabs, so formatting checks must explicitly use `cargo +nightly fmt`. Builds use the stable toolchain. `.cargo/config.toml` sets `RUSTC_BOOTSTRAP=1` and `--cfg reqwest_unstable`; the latter enables the HTTP/3 masquerade test in `tuic-tests`. Do not omit or override these settings during normal validation.

If a change involves Wind, run its formatting, Clippy, and test commands separately from the repository that owns the Wind change. Root workspace validation does not cover the Wind workspace.

## Implementation constraints

- Preserve protocol compatibility, authentication, TLS verification, 0-RTT security semantics, ACL and routing order, traffic accounting, and graceful shutdown behavior. Do not change defaults unless the task explicitly requires it.
- The server supports Quinn and an optional Quiche backend. Quiche is limited to supported 64-bit targets. When changing backend selection or feature gates, keep `Cargo.toml`, `.github/target.toml`, and the target conditions in `tuic-tests` synchronized.
- The client currently uses Quinn. Do not spread server-only Quiche assumptions into client code.
- The root workspace defaults to `aws-lc-rs` and retains a `ring` feature. For TLS or crypto-provider changes, check both feature combinations and avoid installing multiple providers or initializing Rustls without one.
- Propagate errors through `Result` with useful context. The workspace Clippy policy denies `unwrap`, `expect`, `panic!`, `todo!`, and `unimplemented!`. Tests should follow the same style where practical, except where assertion failures are the intended test mechanism.
- Keep public APIs and configuration backward-compatible. Do not refactor adjacent modules, upgrade dependencies, or run a broad `cargo update` unless the task requires it.
- Do not edit generated files directly. Preserve the Quinn Git branch and the `datagram-socket` and `tokio-quiche` patches in the root `Cargo.toml` unless the task explicitly replaces them and validates the alternative.

## Configuration compatibility

Both the server and client accept TOML, JSON/JSON5, and YAML. They determine the format from the file extension, with `TUIC_CONFIG_FORMAT` as an explicit override. Legacy-field migration is part of the compatibility contract.

When changing configuration behavior:

- Reuse the existing defaults, Serde aliases, and migration layer in the relevant `src/config.rs`.
- Add the smallest useful inline unit tests and add fixtures under `tests/config/` when needed.
- Verify modern-format serialization round trips and at least one relevant legacy input.
- Update the corresponding crate `README.md`; update the root `README.md` as well when top-level user-visible behavior changes.
- Never place real UUIDs, passwords, tokens, certificates, private keys, domains, or production endpoints in fixtures or documentation.

## Testing strategy

- Keep configuration parsing, migration, and pure-function tests in the module that owns the behavior.
- Put binary-specific filesystem, routing, and shutdown tests under `tuic-server/tests/` or `tuic-client/tests/`.
- Put cross-endpoint protocol and real loopback-network behavior under `tuic-tests/tests/`, reusing the facilities in `tuic-tests/src/lib.rs`.
- Network tests must use loopback interfaces, temporary directories, temporary certificates, and dynamically allocated ports. Give them explicit timeouts and clean up tasks on success and failure paths.
- Changes to 0-RTT, reconnect behavior, fragmentation, certificate reload, masquerade, or graceful shutdown require the corresponding named integration tests; a successful package compilation alone is insufficient.
- If IPv6, Quiche, cross-compilation, or platform-gated tests cannot run on the current host or toolchain, report what ran and what remains unverified. Do not remove conditional compilation merely to force a test to execute.

## Wind submodule

- `crates/wind/` is an independent repository. Check its `git status --short` and follow `crates/wind/AGENTS.md` plus any deeper instructions.
- Do not develop Wind changes inside `tuic/crates/wind/`. Make shared implementation changes in the sibling top-level `../wind/` repository. During local development, follow the parent repository guide to point TUIC's Wind path dependencies temporarily at that checkout.
- Restore temporary path rewiring before committing TUIC changes. Update this repository's submodule pointer only when the user explicitly asks to adopt a new Wind commit, after receiving approval to commit and push Wind itself.
- Do not mistake uncommitted submodule changes for parent-repository changes, and do not leave an unintended dirty submodule or pointer update.

## CI, release, and security

- `.github/workflows/ci.yml` consumes reusable workflows from `rust-proxy/workflows`. When editing it, check permissions, secret forwarding, target matrices, feature sets, and reusable-workflow input compatibility.
- Do not run releases, create tags, publish images, run stress tests, or contact configured external servers without an explicit request.
- Do not log or echo credentials, certificates, private keys, REST bearer tokens, or real service addresses from local configuration. Tests must use random, temporary, loopback-only material.
- TLS verification bypasses, private or loopback destination access, REST authentication, and 0-RTT are security-sensitive. Any new unsafe option must retain a safe default and clearly document its risk.

## Commits and handoff

- Do not create commits unless the user explicitly requests one.
- Non-trivial AI-assisted changes must include the `Assisted-by: AGENT_NAME:MODEL_VERSION` trailer required by `LLM.md`. Place it after any sign-off trailer.
- Branch changes from `main` and target Pull Requests at `main`; do not use a development branch with rewritable history as a stable base.
- Final summaries must identify the areas changed in the TUIC repository, list the validation actually performed, and call out anything left unverified because of platform, network, certificate, or external dependency constraints.
