# transfer_library

Host-side proving API for the AnomaPay Solana token-transfer resource.

## `TransferLogic`

Wraps a `TokenTransferWitness` and implements ARM's `LogicProver`, so
`logic.prove(proof_type)` produces a `LogicVerifier` for the resource. The
constructors build the witness for each supported flow:

| Constructor | Resource | Flow |
|---|---|---|
| `consume_persistent_resource_logic` | consumed persistent | spend a shielded resource (owner signature) |
| `create_persistent_resource_logic` | created persistent | mint a shielded resource (encrypted payload) |
| `mint_resource_logic_with_wrap_auth` | consumed ephemeral | wrap SPL tokens (Ed25519 authorization) |
| `burn_resource_logic` | created ephemeral | unwrap SPL tokens to a recipient |
| `migrate_resource_logic` | consumed ephemeral | migrate a resource from the previous forwarder |

`migrate_tx::construct_migrate_tx` assembles a complete, balanced ARM
`Transaction` that migrates one resource: compliance unit, both logic proofs,
and the delta proof.

## Guest artifacts

`TOKEN_TRANSFER_ELF` is the prebuilt guest (`elf/token-transfer-guest.bin`) and
`TOKEN_TRANSFER_ID` its RISC0 image ID, the resource's logic reference. Every
change to the ID is recorded in [`VK_HISTORY.md`](VK_HISTORY.md); CI refuses an
ID that is not recorded there.

## Tests

`src/test.rs` proves each flow against the embedded guest. Run with
`RISC0_DEV_MODE=1` for fast, non-cryptographic proofs.
