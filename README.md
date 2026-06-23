# Solana AnomaPay Transfer Resource

Resource logics and zero-knowledge circuits for the **AnomaPay token-transfer
resource** on Solana, targeting the [Anoma Resource Machine (ARM)](https://anoma.net)
on the [RISC Zero](https://dev.risczero.com) zkVM.

This repository packages the witness types, resource-logic library, and RISC
Zero guest program that prove the validity of token-transfer resources backed by
SPL tokens (wrap / unwrap via the SPL token forwarder). It was extracted from the
AnomaPay backend into a standalone workspace so the proving artifacts (guest ELF,
`ImageID`, and the Rust APIs around them) can be versioned and reused
independently of the backend services that consume them.

## Layout

Crates live at the repository root. The witness and library crates form one
Cargo workspace; the circuit is its own **excluded** workspace because the RISC
Zero guest is cross-compiled to the `riscv32im-risc0-zkvm-elf` target and must
not share the host workspace's lockfile or profile.

```
.
├── transfer_witness/   # witness data + resource-logic constraints
├── transfer_library/   # host API: TransferLogic, embedded guest ELF + ImageID
└── transfer_circuit/   # RISC Zero guest program  (excluded workspace)
```

### Dependency graph

```
transfer_witness ──► transfer_library ──► transfer_circuit
                                          (guest embeds the library ELF)
```

- `transfer_witness` is the leaf; everything else builds on it.
- `transfer_library` **embeds the prebuilt guest ELF** (`include_bytes!`) and
  exposes the matching `ImageID`, so a host can verify proofs without rebuilding
  the guest.
- `transfer_circuit` is the guest *source* — used to (re)produce that ELF — and
  depends on the witness/library crates by relative path.

## Crates

### `transfer_witness`
Defines `TokenTransferWitness`: the full set of inputs needed to prove the
resource logic of a single consumed or created resource (the resource itself,
nullifier key, authorization signature, encryption info, forwarder/wrap-auth
data, label and value info). Implements the ARM `LogicCircuit` constraint
function that the guest executes, including the wrap/unwrap external-call
encoding for the SPL token forwarder. Wrapping is authorized by an Ed25519
signature (`WrapAuthInfo`).

### `transfer_library`
Host-side proving API. `TransferLogic` wraps `TokenTransferWitness` with
constructors for the supported flows (consume/create persistent resources, mint
via wrap, burn via unwrap) and implements ARM's `LogicProver`. Embeds the guest
ELF and the matching `TOKEN_TRANSFER_ID` image ID. See
[`transfer_library/VK_HISTORY.md`](transfer_library/VK_HISTORY.md) for the
verifying-key rollback/migration record.

### `transfer_circuit`
The RISC Zero guest program and its `methods` build crate. The guest reads a
`TokenTransferWitness`, runs `constrain()`, and commits the resulting
`LogicInstance`.

## Building

The host workspace builds with a stable toolchain (see
[`rust-toolchain.toml`](rust-toolchain.toml)):

```
cargo build
```

Rebuilding the guest requires the [RISC Zero toolchain](https://dev.risczero.com)
and is done from the excluded `transfer_circuit` workspace.

## Testing

The circuit tests live in `transfer_library` (`src/test.rs`) and prove against
the embedded guest ELF, so they exercise the real resource logic without
rebuilding the guest. Full STARK proving is slow; set `RISC0_DEV_MODE=1` to run
them with fast (non-cryptographic) proofs:

```
RISC0_DEV_MODE=1 cargo test --workspace
```
