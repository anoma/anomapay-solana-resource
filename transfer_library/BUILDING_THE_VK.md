# Building the transfer-circuit VK (`TOKEN_TRANSFER_ID`)

`TOKEN_TRANSFER_ID` is the RISC0 image ID of the token-transfer guest. It is a
hash over the **entire compiled guest ELF**, so it is sensitive to far more than
the circuit logic: the crate names and versions, the source ids of every git
dependency, the guest toolchain, and the **full transitive dependency graph
frozen in the lockfile** all feed it. The only way to get a value that a third
party can reproduce is to make every one of those inputs deterministic.

## Canonical build

Build the guest with the RISC0 Docker reproducible builder, from the repository
root:

```bash
cargo risczero build --manifest-path transfer_circuit/methods/guest/Cargo.toml
```

This compiles the guest inside the pinned `risczero/risc0-guest-builder` image,
which fixes the toolchain and normalizes all source paths. The image ID it
prints is the VK; the ELF it writes is what `transfer_library` embeds. The
`cargo-risczero` that runs the build must be able to build edition-2024 crates
(3.0.5 is known to; the builder image is `r0.1.88.0`).

CI rebuilds the guest the same way and fails if the ELF differs from the
embedded one, and a unit test checks that `TOKEN_TRANSFER_ID` is the image ID
of the embedded ELF, so the checked-in key is always reproducible from the
checked-in source.

## Required invariants

1. **Pin arm-risc0 with the same source the Solana adapter pins (today
   `branch = "main"`), and let the committed lockfiles fix the rev.** Cargo
   treats `?branch=main` and `?rev=<sha>` of the same commit as two sources and
   links both copies of the crates, so a consumer that pins arm-risc0 one way
   cannot share types with a crate that pins it the other way; the adapter's
   fixture generator depends on `transfer_library`, so the two must agree. The
   guest depends on `transfer_witness` by path, and cargo resolves that crate's
   `{ workspace = true }` dependencies against the repository root, so the root
   pin governs the guest too. Because a branch pin re-resolves whenever a
   lockfile is regenerated, never regenerate a lockfile blindly (invariant 3);
   the committed locks are the rev pin.

2. **Any change of a git dependency's source id rotates the VK.** Cargo derives
   each crate's metadata hash from its package id, which includes the git URL,
   branch or tag, and rev. Moving a pin from a branch to a tag, from a rev to a
   branch, or to a newer rev, changes the arm crates' symbol hashes and
   therefore the ELF, even when their source is byte-identical. Plan every
   re-pin, including the lockfile's rev, as a rotation with its own
   `VK_HISTORY.md` row.

3. **Commit BOTH lockfiles (root and guest) with `rev=` git sources and
   transitive versions that compile under the guest toolchain.** After changing
   a pin, convert each lock's git sources in place without bumping the rest:

   ```bash
   # root / host lock
   cargo update -p anoma-rm-risc0          --precise <rev>
   cargo update -p anoma-rm-risc0-gadgets  --precise <rev>
   cargo update -p anoma-pa-solana-client  --precise <rev>
   # guest lock
   cd transfer_circuit/methods/guest
   cargo update -p anoma-rm-risc0          --precise <rev>
   cargo update -p anoma-rm-risc0-gadgets  --precise <rev>
   cargo update -p anoma-pa-solana-client  --precise <rev>
   ```

   Do **not** run a blind `cargo update`. The host cargo resolves transitive
   dependencies to versions the pinned guest toolchain may not build. The
   committed lock is part of the reproducible input; it must be in the commit.

4. **No `trim-paths`, no nightly, no bespoke native build.** The container
   already normalizes paths; a native build produces a VK the standard tool
   cannot reproduce.

## Verify before trusting a VK

- Build twice: identical image ID.
- Build from a checkout at a different absolute path: identical image ID.

Only then set `TOKEN_TRANSFER_ID` in `src/lib.rs`, copy the ELF to
`elf/token-transfer-guest.bin`, and add the row to `VK_HISTORY.md`.
