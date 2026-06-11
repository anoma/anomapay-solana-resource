# transfer_witness

Witness data and resource-logic constraints for the AnomaPay Solana
token-transfer resource. This is the leaf crate of the workspace: it is shared by
the host (`transfer_library`) and compiled into the RISC Zero guest
(`transfer_circuit`), so it carries the single source of truth for what a valid
token-transfer resource looks like.

## What it provides

### `TokenTransferWitness`
The full set of inputs needed to prove the resource logic of one consumed or
created resource: the `Resource` itself, `is_consumed`, the action-tree root, and
the optional `nf_key`, `auth_sig`, `encryption_info`, `forwarder_info`,
`label_info`, and `value_info`.

It implements the ARM `LogicCircuit` trait. `constrain()` dispatches on the
resource kind and produces a `LogicInstance`:

- **ephemeral** → builds the SPL-forwarder external call (`ephemeral_resource_check`):
  - **wrap** (consumed): encodes a `WrapInput` authorized by an Ed25519 signature
    (`WrapAuthInfo`).
  - **unwrap** (created): encodes an `UnwrapInput`, checking the resource
    `value_ref` commits to the recipient Solana account.
- **persistent, consumed** → verifies the authority signature over the action
  root (`persistent_resource_consumption`).
- **persistent, created** → emits the encrypted resource payload and discovery
  ciphertext (`persistent_resource_creation`).

### Supporting types
`EncryptionInfo`, `ForwarderInfo`, `LabelInfo`, `ValueInfo`, `WrapAuthInfo`,
`ResourceWithLabel`, and `CallType` (`Wrap` / `Unwrap`).

### `external_call` module
Wire-level types and helpers for the protocol adapter's external-call subsystem:
`SolanaExternalCall` / `OutputMode` (bincode `encode`/`decode`), the forwarder op
codes `OP_WRAP` / `OP_UNWRAP`, and the instruction-data encoders
`encode_wrap_forwarder_input` (186 bytes) and `encode_unwrap_forwarder_input`
(73 bytes). `call_type` re-exports the op codes and encoders for existing callers.

### Reference helpers
`calculate_label_ref` (forwarder program id + SPL mint), `calculate_persistent_value_ref`
(auth + encryption keys), `calculate_value_ref_from_solana_account`, and
`spl_amount_from_quantity` (rejects quantities above `u64::MAX`).

## Notes

- These shapes must match the protocol adapter byte-for-byte: the external-call
  blob is serialized off-chain and read on-chain by the same definitions.
- Unit tests for the forwarder encoders and external-call round-trips live in
  this crate. End-to-end proving tests live in
  [`transfer_library`](../transfer_library).
