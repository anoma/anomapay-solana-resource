# transfer_circuit_v2

The v2 RISC Zero guest program for the AnomaPay Solana token-transfer resource,
with migration support.

This is its **own Cargo workspace**, excluded from the repository root workspace:
the guest is cross-compiled to the `riscv32im-risc0-zkvm-elf` target and must not
share the host workspace's lockfile or build profile.

## Layout

```
transfer_circuit_v2/
├── src/main.rs            # host binary: reports / dumps the guest ELF + ImageID
└── methods/               # `token-transfer-methods-v2` build crate
    ├── build.rs           # risc0_build::embed_methods()
    └── guest/             # `token-transfer-guest-v2`: the guest program
```

- **`methods`** runs `risc0-build` at compile time to compile the guest and
  generate `TOKEN_TRANSFER_GUEST_V2_ELF` and `TOKEN_TRANSFER_GUEST_V2_ID`.
- **`methods/guest`** is the guest entry point: it reads a
  `TokenTransferWitnessV2`, runs `constrain()` from
  [`transfer_witness_v2`](../transfer_witness_v2), and commits the resulting
  `LogicInstance`. (`borsh` is pinned `<1.6` there so its derive macro stays
  optional and does not break guest cross-compilation.)
- **`src/main.rs`** is a host helper, not the prover: it prints the image ID
  (hex) and ELF size, and with `--dump-elf <path>` writes the guest ELF that
  [`transfer_library_v2`](../transfer_library_v2) embeds.

## Reproducibly building the ELF and ImageID

`ImageID`s differ across machines and environments. To reproduce a publicly
verifiable ELF / `ImageID` that corresponds to this guest source, use the
docker-based reproducible build from the repository root
([RISC Zero toolchain](https://dev.risczero.com) required):

```bash
cargo risczero build --manifest-path transfer_circuit_v2/methods/guest/Cargo.toml
```

To embed a freshly built guest, copy that ELF over
[`transfer_library_v2/elf/token-transfer-guest-v2.bin`](../transfer_library_v2/elf/token-transfer-guest-v2.bin)
and set `TOKEN_TRANSFER_V2_ID` in
[`transfer_library_v2/src/lib.rs`](../transfer_library_v2/src/lib.rs) to the
printed `ImageID`.

See [`transfer_circuit`](../transfer_circuit) for the v1 guest and additional
notes on `ImageID` drift.
