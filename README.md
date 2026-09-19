# Solana AnomaPay Transfer Resource

Resource logic and zero-knowledge circuit for the **AnomaPay token-transfer
resource** on Solana, targeting the [Anoma Resource Machine (ARM)](https://anoma.net)
on the [RISC Zero](https://dev.risczero.com) zkVM.

This repository packages the witness types, the resource-logic library, and the
RISC Zero guest program that prove the validity of token-transfer resources
backed by SPL tokens: wrap and unwrap through the SPL token forwarder, and
transfers between shielded owners. The proving artifacts (guest ELF, `ImageID`, and the Rust APIs around
them) are versioned here independently of the services that consume them.

## Layout

Crates live at the repository root. The witness and library crates form one
Cargo workspace; the circuit is its own **excluded** workspace because the RISC
Zero guest is cross-compiled to the `riscv32im-risc0-zkvm-elf` target and must
not share the host workspace's lockfile or profile.

```
.
├── transfer_witness/      # witness data + resource-logic constraints
├── transfer_library/      # host API: TransferLogic, embedded guest ELF + ImageID
└── transfer_circuit/      # RISC Zero guest program (excluded package)
```

### Dependency graph

```
transfer_witness ──► transfer_circuit ──(ELF)──► transfer_library
```

- `transfer_witness` is the leaf; the guest and the library both build on it.
- `transfer_circuit` is the guest *source*, depending on the witness crate by
  relative path (its `{ workspace = true }` pins resolve against this root);
  building it produces the guest ELF and its `ImageID`.
- `transfer_library` **embeds that prebuilt guest ELF** (`include_bytes!`) and
  exposes the matching `ImageID`, so a host can prove and verify without
  rebuilding the guest.

## Crates

### `transfer_witness`
Defines `TokenTransferWitness`: the inputs needed to prove the resource logic of
one consumed or created resource (the resource itself, nullifier key,
authorization signature, encryption info, forwarder call data, label and value
info). Implements the ARM `LogicCircuit` constraint function the guest executes,
including the wrap and unwrap external-call encodings for the SPL token
forwarder. Wrapping is authorized by an Ed25519 signature carried in the
settlement transaction (`WrapAuthInfo` names the instruction).

### `transfer_library`
Host-side proving API. `TransferLogic` wraps `TokenTransferWitness` with
constructors for the supported flows (consume and create persistent resources,
mint via wrap, burn via unwrap) and implements ARM's `LogicProver`. The
`action` module builds a whole wrap or unwrap from keys and amounts: the
resources it consumes and creates, the message the user signs, and the
compliance and logic witnesses of the action, proven in-process or by the
caller's prover. Embeds the guest ELF and the matching `TOKEN_TRANSFER_ID` image ID. See
[`transfer_library/VK_HISTORY.md`](transfer_library/VK_HISTORY.md) for the
verifying-key history and the migration record of every rotation.

### `transfer_circuit`
The RISC Zero guest program. It reads a `TokenTransferWitness`, runs
`constrain()`, and commits the resulting `LogicInstance`.

## Building

The host workspace builds with a stable toolchain (see
[`rust-toolchain.toml`](rust-toolchain.toml)):

```
cargo build
```

Rebuilding the guest requires the [RISC Zero toolchain](https://dev.risczero.com)
and the reproducible builder; see
[`transfer_library/BUILDING_THE_VK.md`](transfer_library/BUILDING_THE_VK.md).

## Testing

The circuit tests live in `transfer_library` (`src/test.rs`) and prove against
the embedded guest ELF, so they exercise the real resource logic without
rebuilding the guest. Full STARK proving is slow; set `RISC0_DEV_MODE=1` to run
them with fast (non-cryptographic) proofs:

```
RISC0_DEV_MODE=1 cargo test --workspace
```

## Versioning

The workspace crates (`transfer_witness`, `transfer_library`) share the version
in `[workspace.package]`. The circuit crate is versioned independently.

## License

GPL-3.0.
