# Transfer-logic v2 verifying-key history

The `TOKEN_TRANSFER_V2_ID` constant in `src/lib.rs` is the RISC0 image ID of the
v2 token-transfer circuit guest (the migration-capable resource logic).
**Changing it orphans every persistent shielded resource minted under the prior
VK** — the prover infrastructure only carries the binary for the current circuit,
so old resources cannot be consumed via normal proving. This file is the
rollback / migration record for those changes.

CI (`scripts/check-vk-history-v2.sh`) refuses to merge a change to
`TOKEN_TRANSFER_V2_ID` unless the new value appears in the table below. Adding
an entry is the author's commitment that the migration plan has been thought
through. Operational consequences (paused withdrawals, dual-prover support,
emergency-caller drains, communication to affected wallets) are NOT
automated — the table is a forcing function for the conversation, not a
substitute for it.

See [`../transfer_library/VK_HISTORY.md`](../transfer_library/VK_HISTORY.md) for
the v1 history.

## Format

Each row is `VK | commit | date | reason | migration`. VK is lowercase hex,
no `0x` prefix.

| VK | Commit | Date | Reason | Migration plan |
|---|---|---|---|---|
| `63eb06506a4596fc5d4359084785e68f54e59a31bd535518038f829f9e164105` | (this commit) | 2026-06-23 | Initial Solana port of the v2 (migration-capable) token-transfer guest, adapted from the ERC20 v2 resource. Local (non-reproducible) build; the resource logic adds the `Migrate` call type on top of the v1 wrap/unwrap logic. | None — not deployed. v2 has never shipped to mainnet, so no resources are minted under this VK and nothing is orphaned. The migration plan must be revisited (including a reproducible docker build of the guest) before this VK ships to a live network. |

## Process for adding a new VK

1. Rebuild the guest, write the new image ID to `src/lib.rs::TOKEN_TRANSFER_V2_ID`.
2. Add a new row to the table above with:
   - the new VK (lowercase hex),
   - the commit that introduces it (use `(this commit)` until the SHA is known),
   - the date in ISO format,
   - a one-sentence reason that names what changed in the circuit,
   - the migration plan — how holders of pre-bump resources will spend or recover them. Acceptable values: a link to the migration script PR, "dual-prover support added in <commit>", "no migration available, coordinate with affected wallets per <thread>", etc. **"None"** is also acceptable if there are demonstrably no in-flight resources at the upgrade slot, but the comment must say so explicitly so reviewers can verify.
3. Commit and push. CI runs `scripts/check-vk-history-v2.sh`; if it fails, the diff between code and history is the actionable fix.
