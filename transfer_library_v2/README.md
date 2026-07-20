# transfer_library_v2

Host-side proving API for the **v2 AnomaPay Solana token-transfer resource**. It
wraps [`transfer_witness_v2`](../transfer_witness_v2) with ergonomic constructors,
adds the migration transaction builder, and embeds the prebuilt v2 RISC Zero
guest, so a host can build and verify proofs without the RISC Zero toolchain.

It mirrors [`transfer_library`](../transfer_library) and adds the migration flow.

## What it provides

### `TransferLogicV2`
Wraps a `TokenTransferWitnessV2` and implements ARM's `LogicProver`. Constructors
cover the supported flows:

- `mint_resource_logic_with_wrap_auth` — mint via **wrap** (Ed25519-authorized).
- `burn_resource_logic` — burn via **unwrap** to a recipient Solana account.
- `consume_persistent_resource_logic` — consume a persistent resource (authority
  signature).
- `create_persistent_resource_logic` — create a persistent resource (with
  discovery + encryption payloads).
- `migrate_resource_logic` — **new in v2**: migrate a v1 resource into v2.

### `construct_migrate_tx` ([`migrate_tx.rs`](src/migrate_tx.rs))
Builds the full migration `Transaction`: a compliance unit, the consumed
(ephemeral, `Migrate`) and created (persistent) logic proofs, and the balanced
delta proof. The delta message is hashed with Keccak256 (`hash_msg_keccak`),
matching the ARM delta-proof convention.

### Embedded verifying artifacts
- `TOKEN_TRANSFER_V2_ELF` — the v2 guest ELF, embedded with `include_bytes!` from
  `elf/token-transfer-guest-v2.bin`.
- `TOKEN_TRANSFER_V2_ID` — the matching image ID (`Digest`), returned as the
  `LogicProver` verifying key.

See [`VK_HISTORY.md`](VK_HISTORY.md) for the verifying-key rollback/migration
record. The ELF is regenerated from the
[`transfer_circuit_v2`](../transfer_circuit_v2) guest workspace.

## Testing

Circuit tests in [`src/test.rs`](src/test.rs) prove against the embedded ELF,
covering wrap/unwrap/transfer and the migration path (positive + negative). Full
STARK proving is slow; use dev mode for fast (non-cryptographic) proofs:

```
RISC0_DEV_MODE=1 cargo test -p transfer_library_v2
```
