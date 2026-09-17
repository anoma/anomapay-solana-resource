# transfer_witness

Witness data and resource-logic constraints for the AnomaPay Solana
token-transfer resource.

## `TokenTransferWitness`

Everything a proof of one resource's logic needs:

```rust
pub struct TokenTransferWitness {
    pub resource: Resource,
    pub is_consumed: bool,
    pub action_tree_root: Digest,
    pub nf_key: Option<NullifierKey>,                // consumed resources
    pub auth_sig: Option<AuthoritySignature>,        // consumed persistent resources
    pub encryption_info: Option<EncryptionInfo>,     // created persistent resources
    pub forwarder_info: Option<ForwarderInfo>,       // ephemeral resources
    pub label_info: Option<LabelInfo>,
    pub value_info: Option<ValueInfo>,
}
```

`constrain()` (the ARM `LogicCircuit` implementation the guest runs) dispatches
on the resource:

- **ephemeral** — the resource triggers a forwarder call. The label must be
  `sha256(forwarder_program_id ‖ spl_token_mint)`, and the call is encoded into
  the instance's `external_payload` as a `SolanaExternalCall` (`Wrap` from a
  consumed resource, `Unwrap` to the recipient a created resource's `value_ref`
  names, `Migrate` from a consumed resource carrying `MigrateInfo`).
- **consumed persistent** — the owner's authorization signature over the action
  tree root, under `AUTH_SIGNATURE_DOMAIN`, must verify against the `auth_pk` in
  the resource's `value_ref`.
- **created persistent** — the label is checked, and the resource plus its label
  plaintext are encrypted to the owner's `encryption_pk` into the instance's
  `resource_payload`, with a discovery ciphertext in `discovery_payload`.

## Supporting types

- `ForwarderInfo { call_type, solana_account, wrap_auth_info, migrate_info }`
- `WrapAuthInfo { nonce, deadline, ed25519_signature, ed25519_ix_index }` — the
  Ed25519 wrap authorization the settlement transaction carries.
- `MigrateInfo` — the resource being migrated from the previous forwarder, its
  nullifier key, Merkle path, authorization signature, value info and forwarder
  program id.
- `LabelInfo`, `ValueInfo`, `EncryptionInfo`, `ResourceWithLabel`.
- `calculate_label_ref`, `calculate_persistent_value_ref`,
  `calculate_value_ref_from_solana_account`, `spl_amount_from_quantity`.

## `call_type`

`CallType { Wrap, Unwrap, Migrate }`. The op codes and instruction-data encoders
are owned by `anoma-pa-solana-client` and re-exported here, so the circuit and
the on-chain forwarder agree byte for byte.
