# kotoba-server — retired source, still deployed

**This repository is an address, not a project.** It exists so that a binary
which is currently running on production machines can be *identified*. It is
**not** a resumption of Rust development, and nothing here should be built.

## What this is

`kotoba-server` is a Rust crate that was deleted from `kotoba-lang/kotoba` on
**2026-07-01** under the no-Rust policy of
[ADR-2607072000](../../90-docs/adr/2607072000-kotoba-rust-avoidance-policy-and-kotoba-server-gap.edn).
That ADR named it as the one crate with **no cljc successor** which nevertheless
**stayed deployed**, and deliberately did not start its migration.

The compiled artifact is still resident as an always-on daemon on fleet
machines. Its build is pinned in `bin/BUILD.edn` in `kotoba-lang/murakumo` to a
commit that, after the deletion, was recoverable **only from git history** — it
existed in no checkout, no west pin, and no default branch tree.

This repository gives that source an address.

## The pinned commit

```
4f38b74afd671c0f44667f55c24517600e384ba1
```

- Authored **2026-06-27**, subject:
  `feat(kotoba-server): webrtc feature → kotoba-net/webrtc (buildable fleet binary)`
- Verified **an ancestor of `kotoba-lang/kotoba`'s `origin/main`**, 643 commits
  back, in a full (non-shallow) clone. It is *not* one branch deletion away from
  being lost; GitHub retains it for as long as `main` exists.
- Recorded build invocation (from `BUILD.edn`):
  `cargo build --release -p kotoba-server --features p2p,realtime-wasm,webrtc`
  plus `-p kotoba-cli`, target `aarch64-apple-darwin`.

## What is preserved here, and why the whole workspace

`workspace/` is a **verbatim copy of the repository tree at the pinned commit**,
with one deletion described below. It is not the crate directory alone, because
the crate cannot build alone:

- The workspace root manifest declares **36 members** (33 crates + 3 examples)
  and cargo must parse *all* of them to build any one.
- `crates/kotoba-server` alone has **19 direct path-dependencies** on sibling
  crates in this workspace.
- The lockfile is workspace-wide, and `[workspace.dependencies]` centralises
  version selection.

Measured: 806 files, 13 MB, 41 `.rs` files under `crates/kotoba-server/src`.

### The one exclusion

`crates/kotoba-kotodama` (39 MB) is **not** included. It is not part of this
cargo workspace — the workspace root manifest excludes it in its own comment as
"its own nested workspace root (separate TS-native / e7m build pipeline)". It is
not a workspace member, not a path-dependency of any member, and **does not
appear in the workspace lockfile**. All three were checked.

Everything else at the pinned commit is byte-identical, including `.github/`.
Note that those workflow files sit at `workspace/.github/`, **not** at the
repository root, so GitHub will not execute them — which is what we want, since
CI/CD authority in this workspace is the murakumo fleet, not GitHub Actions.

## What is NOT preserved — the honest limits

Preserving the source does **not** make this rebuildable, and it must not be
read as if it did.

- **There is no `rust-toolchain.toml`.** Confirmed absent from the entire tree at
  the pinned commit. The compiler version is therefore **unpinned**: nothing here
  records which `rustc` produced the running binary.
- **`.cargo/config.toml` sets `rustflags = ["-C", "target-cpu=native"]`.** A
  rebuild is therefore **never byte-identical** — it is tuned to whatever CPU
  compiled it. This is the decisive limitation: a recorded checksum can
  **authenticate** the deployed artifact, but it can **never be re-derived** by
  rebuilding.
- **The dependency closure is promising but unmeasured.** The lockfile is
  **v4 with 1,056 packages, 1,020 of them from crates.io, and `source = "git+"`
  appears exactly ZERO times.** No git dependencies is the single best available
  fact for future rebuildability, since crates.io is immutable and continues to
  serve yanked versions. **But this was inferred by reading the lockfile, not
  measured — nobody has run a fetch.** Treat "the closure still resolves" as
  likely, not established.
- **No checksum binds the artifact to this commit.** At the time of writing, a
  hash of the deployed binary exists only as an 8-character prefix in prose, and
  the two records that mention it disagree about whether it covers one binary or
  two. **Nobody has verified that the deployed binary was built from this
  commit.** This repository preserves the *claimed* source; it does not prove
  provenance.

## Before anyone builds this

Do not build it to "see if it still works". A green build would prove very
little (see `target-cpu=native` above) and a deployment would touch a live
fleet. The prerequisites are policy, not convenience:

1. **A dedicated ADR.** ADR-2607072000 decision 3 defers `kotoba-server`
   explicitly and requires a dedicated ADR containing a **staged cutover**
   (parallel run → parity verification → switch), **measured performance
   requirements**, and a **rollback path**. Preserving this source is what makes
   that rollback clause satisfiable at all — rollback requires that the artifact
   you roll back to be identifiable.
2. **Record the artifact first.** Compute the full sha256 of the deployed binary
   on a node and record it against this commit, stating in the record that the
   build is *not* bit-reproducible so the hash reads as an authenticity anchor
   rather than a reproducibility claim.
3. **Pin a toolchain and measure the closure.** Add a `rust-toolchain.toml` and
   actually run a fetch to convert the rebuildability inference above into a
   measurement.
4. **Address the security findings before anything is redeployed.** This binary
   exposes 24 operator-authenticated endpoints whose bearer check does not verify
   signatures, plus an unauthenticated route that rewrites the mesh routing
   table. These are documented in ADR-2608123600 and ADR-2608124000. Restoring
   the source does not restore the assumptions it was written under.

## Naming

`kotoba-server`, under `kotoba-lang`, per `manifest/repository-rules.edn`'s
`:plane-order`: the **origin** plane does not apply (this is our own code), the
**role** plane has no prefix covering a daemon, and the **family** plane does —
`kotoba-` is a declared family with 32 members. Existing family form takes
precedence over the org-elision rule. No language suffix is appended; the `-clj`
prohibition applies to names, and this is not a language identity.

## Related

- ADR-2607072000 — the no-Rust policy, and the decision *not* to migrate this crate
- ADR-2608123600 — the operator bearer credential
- ADR-2608124000 — the ownership gap this repository closes
