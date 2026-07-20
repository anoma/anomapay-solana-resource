# transfer_witness_v2

The v2 witness crate for the **AnomaPay Solana token-transfer resource**. It
mirrors [`transfer_witness`](../transfer_witness) — same wrap/unwrap logic against
the SPL token forwarder — and adds **migration** support for moving a v1 resource
to v2.

It reuses the v1 building blocks directly (`EncryptionInfo`, `LabelInfo`,
`ValueInfo`, `WrapAuthInfo`, `ResourceWithLabel`, the `SolanaExternalCall` wire
types, and the `calculate_*` / `spl_amount_from_quantity` helpers), so v2 only
adds what changes: the forwarder shape and the migration call type.

## What's new relative to v1

### `TokenTransferWitnessV2`
Same fields as `TokenTransferWitness`, except `forwarder_info` is replaced by
`forwarder_info_v2: Option<ForwarderInfoV2>`.

### `ForwarderInfoV2`
```rust
pub struct ForwarderInfoV2 {
    pub call_type: CallTypeV2,            // Wrap | Unwrap | Migrate
    pub solana_account: Option<[u8; 32]>, // recipient/payer; not needed for Migrate
    pub wrap_auth_info: Option<WrapAuthInfo>, // present only for Wrap
    pub migrate_info: Option<MigrateInfo>,    // present only for Migrate
}
```

### `MigrateInfo`
The extra data a `Migrate` call proves about the **v1 resource being migrated**:
its `Resource`, nullifier key, a Merkle `path` from the v1 commitment tree
(proving the resource existed), the owner's authorization signature and
`ValueInfo`, and the **v1** forwarder program id used in its label.

### `CallTypeV2` ([`call_type_v2.rs`](src/call_type_v2.rs))
Adds `Migrate` to `Wrap`/`Unwrap`. All op codes and instruction-data encoders are
owned by `anoma-pa-solana-client` (so the circuit and the on-chain forwarder
agree byte-for-byte): `Wrap`/`Unwrap` are re-exported via
[`transfer_witness::call_type`], and the v2-only `OP_MIGRATE` /
`encode_migrate_forwarder_input` come from the same client crate. The migrate
layout is `op(1) + token_mint(32) + amount_le(8) + nullifier(32) + root_v1(32) +
logic_ref_v1(32) + forwarder_v1(32)` (169 bytes).

Only `MIGRATE_FORWARDER_NUM_ACCOUNTS` lives here.

> `MIGRATE_FORWARDER_NUM_ACCOUNTS` must match the migrate instruction of the
> deployed v2 SPL token forwarder. It is provisional until that program is
> finalized — revisit before shipping migration to a live network.

## The migration constraint

When `constrain()` runs on an ephemeral resource with `CallTypeV2::Migrate`, it
enforces (in [`src/lib.rs`](src/lib.rs)):

- migration must be triggered by a **consumed** resource;
- the migrated v1 resource is **non-ephemeral**;
- its `value_ref` matches its `ValueInfo`, and the owner's authorization
  signature over the action tree root verifies under
  `TokenTransferAuthorizationV2`;
- its quantity equals the v2 resource's quantity (and fits in `u64`);
- its `label_ref` matches `sha2(v1_forwarder_program_id, spl_token_mint)`;

then it derives the migrated resource's nullifier and Merkle root and emits the
`Migrate` forwarder external call as the external payload.

`Wrap` and `Unwrap` behave as in v1.

## Where it's used

- [`transfer_library_v2`](../transfer_library_v2) wraps this witness behind
  `TransferLogicV2` and builds the migration transaction.
- [`transfer_circuit_v2`](../transfer_circuit_v2) reads a
  `TokenTransferWitnessV2` in the guest and calls `constrain()`.

## Testing

End-to-end proving tests live in [`transfer_library_v2`](../transfer_library_v2).

```bash
cargo test -p transfer_witness_v2
```

See the [workspace README](../README.md) for the full picture.
