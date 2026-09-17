# Transfer-logic verifying-key history

The `TOKEN_TRANSFER_ID` constant in `src/lib.rs` is the RISC0 image ID of the
token-transfer circuit guest. **Changing it orphans every persistent shielded
resource minted under the prior VK** unless a migration path exists: the prover
infrastructure only carries the binary for the current circuit, so old resources
cannot be consumed through normal proving. This file is the rollback / migration
record for those changes.

CI (`scripts/check-vk-history.sh`) refuses to merge a change to
`TOKEN_TRANSFER_ID` unless the new value appears in one of the tables below.
Adding an entry is the author's commitment that the migration plan has been
thought through. Operational consequences (paused withdrawals, dual-prover
support, emergency-caller drains, communication to affected wallets) are NOT
automated: the table is a forcing function for the conversation, not a
substitute for it.

## Format

Each row is `VK | commit | date | reason | migration`. VK is lowercase hex,
no `0x` prefix.

## V1 line (mainnet)

The V1 crates lived in this repository until the ARM v2 port and are the logic
the mainnet V1 forwarder pins. The live mainnet V1 key is `9bda007d…`; the on-chain
forwarder config is the source of truth for which key is live.

| VK | Commit | Date | Reason | Migration plan |
|---|---|---|---|---|
| `8bceee49ac4646f7bf1ba20be658be5ab5699ce5cab58004f44efaa900717384` | (pre-Apr 2026) | — | Original Solana port build of the token-transfer guest. | N/A — first VK, nothing to migrate from. |
| `3fcc1fb95b4a61b7105e30b1c107024c72fb9bdb3f4c6755da0a39864db5ac23` | `0eb3f0c9f84e3fa3c2fae350e03bedf797e07eec` | 2026-04-13 | Forced rebuild after H-001 fix changed `LogicVerifierInputs` / `LogicInstance` serialization. Old guest journals no longer matched the PA's on-chain re-derivation. | No migration available at upgrade time — pre-H-001 shielded resources became unspendable. |
| `9bda007dd983c27f733663dc3c84a49e14dcf5a6d65958494f51ccb77fd8ed84` | `cfa7f6a1bdf17a376c671e4b05eac9165da21e05` | 2026-05-06 | Added in-circuit guard rejecting SPL token quantities that would overflow `u64` on the unwrap path (the `u256 → u64` truncation surface). Required rebuilding the guest, which rotated the VK. | No migration available at upgrade time — wraps minted between 2026-04-13 and 2026-05-06 became unspendable through normal proving. Recovered out-of-band via the SPL token forwarder's emergency-caller mechanism on 2026-05-26 during the P-002 mainnet upgrade window. |
| `5a033ade10bb3af30f8a34c31f73b6702b4ba5cbe42ce9cd1dd4835ef0c768f6` | `caf3c8b1772d6773a743c74d70dda9a81bbc0284` | 2026-06-19 | Repo-migration refactor (move out of the backend repo): package renames, per-crate versioning, and sourcing the external-call types from `anoma-pa-solana-client` changed the crate metadata and type definitions embedded in the guest ELF, rebuilding it. No circuit logic changed; the VK rotated incidentally. Two transient intermediate values (`900df4f9…` at `7e82d68`, `9dd36169…` at `f0190b0`) appeared during the refactor and are omitted — they never left this branch. | None — not deployed. `9bda007…` remains the live mainnet VK; no resources have been minted under `5a033ade…` (or the intermediate values), so nothing is orphaned. The migration plan, if any, must be revisited before this VK ships to mainnet. |

## V2 line

| VK | Commit | Date | Reason | Migration plan |
|---|---|---|---|---|
| `93e00f30c272a747fbd48c0938ea71842e88a34db15cebc4fff3f451c320588d` | (this commit) | 2026-06-24 | Initial Solana port of the v2 (migration-capable) token-transfer guest, adapted from the ERC20 v2 resource. The `Migrate` call type is added on top of the v1 wrap/unwrap logic, sourcing `OP_MIGRATE` / `encode_migrate_forwarder_input` from `anoma-pa-solana-client`. Local (non-reproducible) build. (Transient intra-branch values `c9f22b83…`, `e76734b0…`, and `63eb0650…` appeared while iterating on versioning and the encoder source; they never left this branch and are omitted.) | None — not deployed. v2 has never shipped to mainnet, so no resources are minted under this VK and nothing is orphaned. The migration plan must be revisited (including a reproducible docker build of the guest) before this VK ships to a live network. |
| `134aaf7eb176858c0e1b68f990ef9e8bd691603c7bd13ad0c1976219df207b2d` | (this commit) | 2026-09-17 | ARM v2 port: arm-risc0 `main` at `5085021f` (v2.0.0-rc.5 plus the Solana crates), anoma-pa-solana-client `9cd3752e`; the V2 SPL token forwarder's segments (wrap 8 accounts, unwrap 7) and its 122-byte wrap input without the ed25519 signature; the migrate call removed (its redesign is anoma/dos-pm#42, the Solana port anoma/dos-pm#77). Reproducible Docker build with cargo-risczero 3.0.5 (builder `r0.1.88.0`), identical from two in-place builds and one from another path; CI rebuilds and compares. | None — V2 is a fresh deployment; no resource has been minted under any prior V2 key. Expected future rotations: the re-pin to the next arm-risc0 release tag, the migrate port (dos-pm#77 after dos-pm#42), anomapay-pm#58, arm-risc0#252. |

## Process for adding a new VK

1. Rebuild the guest, write the new image ID to `src/lib.rs::TOKEN_TRANSFER_ID`.
2. Add a new row to the table above with:
   - the new VK (lowercase hex),
   - the commit that introduces it (use `(this commit)` until the SHA is known),
   - the date in ISO format,
   - a one-sentence reason that names what changed in the circuit,
   - the migration plan — how holders of pre-bump resources will spend or recover them. Acceptable values: a link to the migration script PR, "dual-prover support added in <commit>", "no migration available, coordinate with affected wallets per <thread>", etc. **"None"** is also acceptable if there are demonstrably no in-flight resources at the upgrade slot, but the comment must say so explicitly so reviewers can verify.
3. Commit and push. CI runs `scripts/check-vk-history.sh`; if it fails, the diff between code and history is the actionable fix.
