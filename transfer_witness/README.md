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
  names).
- **consumed persistent** — the owner's authorization signature over the action
  tree root, under `AUTH_SIGNATURE_DOMAIN`, must verify against the `auth_pk` in
  the resource's `value_ref`.
- **created persistent** — the label is checked, and the resource plus its label
  plaintext are encrypted to the owner's `encryption_pk` into the instance's
  `resource_payload`, with a discovery ciphertext in `discovery_payload`.

## Supporting types

- `ForwarderInfo { call_type, solana_account, wrap_auth_info }`
- `WrapAuthInfo { nonce, deadline, ed25519_ix_index }` — the nonce and deadline
  the user signed and the settlement-transaction index of the ed25519
  instruction carrying the signature.
- `LabelInfo`, `ValueInfo`, `EncryptionInfo`, `ResourceWithLabel`.
- `calculate_label_ref`, `calculate_persistent_value_ref`,
  `calculate_value_ref_from_solana_account`, `spl_amount_from_quantity`.

## `call_type`

`CallType { Wrap, Unwrap }` and the account count of each call's CPI segment
(`WRAP_SEGMENT_NUM_ACCOUNTS`, `UNWRAP_SEGMENT_NUM_ACCOUNTS`). The op codes and
instruction-data encoders are owned by `anoma-pa-solana-client`, so the circuit
and the on-chain forwarder agree byte for byte.
