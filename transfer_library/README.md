# transfer_library

Host-side proving API for the AnomaPay Solana token-transfer resource. It wraps
[`transfer_witness`](../transfer_witness) with ergonomic constructors and embeds
the prebuilt RISC Zero guest, so a host can build and verify proofs without the
RISC Zero toolchain.

## What it provides

### `TransferLogic`
Wraps a `TokenTransferWitness` and implements ARM's `LogicProver`. Constructors
cover the supported flows:

- `mint_resource_logic_with_wrap_auth` — mint via **wrap** (Ed25519-authorized).
- `burn_resource_logic` — burn via **unwrap** to a recipient Solana account.
- `consume_persistent_resource_logic` — consume a persistent resource (authority
  signature).
- `create_persistent_resource_logic` — create a persistent resource (with
  discovery + encryption payloads).

### Embedded verifying artifacts
- `TOKEN_TRANSFER_ELF` — the guest ELF, embedded with `include_bytes!` from
  `elf/token-transfer-guest.bin`.
- `TOKEN_TRANSFER_ID` — the matching image ID (`Digest`), returned as the
  `LogicProver` verifying key.

See [`VK_HISTORY.md`](VK_HISTORY.md) for the verifying-key rollback/migration
record. The ELF is regenerated from the [`transfer_circuit`](../transfer_circuit)
guest workspace.

## Testing

Circuit tests in [`src/test.rs`](src/test.rs) prove against the embedded ELF, so
they exercise the real resource logic without rebuilding the guest. Full STARK
proving is slow; use dev mode for fast (non-cryptographic) proofs:

```
RISC0_DEV_MODE=1 cargo test -p transfer_library
```
