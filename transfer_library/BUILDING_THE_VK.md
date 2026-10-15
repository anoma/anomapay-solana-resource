# Building the circuit VKs

This repository has two circuits, each a guest whose RISC0 image ID is a VK:

| Circuit | Guest | Library | VK |
|---|---|---|---|
| `transfer_circuit` | `token-transfer-guest` | `transfer_library` | `TOKEN_TRANSFER_ID` |
| `emergency_migrating_transfer_circuit` | `emergency-migrating-token-transfer-guest` | `emergency_migrating_transfer_library` | `EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID` |

Everything below holds for both. A VK is a
hash over the **entire compiled guest ELF**, so it is sensitive to far more than
the circuit logic: the crate names and versions, the source ids of every git
dependency, the guest toolchain, and the **full transitive dependency graph
frozen in the lockfile** all feed it. The only way to get a value that a third
party can reproduce is to make every one of those inputs deterministic.

## Canonical build

Build each guest with the RISC0 Docker reproducible builder, from the repository
root:

```bash
cargo risczero build --manifest-path transfer_circuit/Cargo.toml
cargo risczero build --manifest-path emergency_migrating_transfer_circuit/Cargo.toml
```

This compiles the guest inside the pinned `risczero/risc0-guest-builder` image,
which fixes the toolchain and normalizes all source paths. The image ID it
prints is the VK; the ELF it writes is what its library embeds. The
`cargo-risczero` that runs the build must be able to build edition-2024 crates
(3.0.5 is known to; the builder image is `r0.1.88.0`).

CI rebuilds each guest the same way and fails if the ELF differs from the
embedded one, and a unit test in each library checks that its VK is the image
ID of the embedded ELF, so the checked-in keys are always reproducible from the
checked-in source.

## Required invariants

1. **Take arm-risc0 from the same source the Solana adapter does (today
   crates.io, `2.0.0-rc.7`), and let the committed lockfiles fix the version.**
   The requirement is a caret one, as the ERC20 resource's: a consumer that
   links this crate with other circuit crates (the kind tables link every
   active circuit) resolves one arm-risc0 for all of them, and an exact
   requirement would refuse any release but this one. The lockfiles, not the
   requirement, fix what the guest builds with. Cargo
   treats `?branch=main` and `?rev=<sha>` of the same commit as two sources and
   links both copies of the crates, so a consumer that pins arm-risc0 one way
   cannot share types with a crate that pins it the other way; the SPL token
   forwarder's integration tests depend on `transfer_library` and on the
   adapter's harness, so the two must agree. The
   guests depend on their witness crates by path, and cargo resolves those
   crates' `{ workspace = true }` dependencies against the repository root, so
   the root pin governs the guests too. Never regenerate a lockfile blindly (invariant
   3): the committed locks fix every version the guest builds with.

2. **Any change of a git dependency's source id rotates the VK.** Cargo derives
   each crate's metadata hash from its package id, which includes the git URL,
   branch or tag, and rev. Moving a pin from a branch to a tag, from a rev to a
   branch, or to a newer rev, changes the arm crates' symbol hashes and
   therefore the ELF, even when their source is byte-identical. Plan every
   re-pin as a rotation with its own `VK_HISTORY.md` row.

3. **Commit every lockfile (the root's and each guest's) with the git sources
   the manifest names and transitive versions that compile under the guest
   toolchain.** The Solana crates are pinned by their release tags
   (`bindings/v*`), or by commit while the commit the circuits need is not
   released yet. After changing a pin, re-lock that source in each lock without
   bumping the rest (`cargo fetch` resolves only what the manifest changed):

   ```bash
   # root / host lock
   cargo fetch
   # guest locks
   (cd transfer_circuit && cargo fetch)
   (cd emergency_migrating_transfer_circuit && cargo fetch)
   ```

   The forwarder client depends on `anoma-pa-solana-client` itself; pin the
   adapter client at the tag the forwarder client pins, or the guest links two
   copies of it.

   Do **not** run a blind `cargo update`. The host cargo resolves transitive
   dependencies to versions the pinned guest toolchain may not build. The
   committed lock is part of the reproducible input; it must be in the commit.

4. **No `trim-paths`, no nightly, no bespoke native build.** The container
   already normalizes paths; a native build produces a VK the standard tool
   cannot reproduce.

## Verify before trusting a VK

- Build twice: identical image ID.
- Build from a checkout at a different absolute path: identical image ID.

Only then set the VK in the library's `src/lib.rs`, copy the ELF to the
library's `elf/<guest>.bin`, and add the row to the library's `VK_HISTORY.md`.
