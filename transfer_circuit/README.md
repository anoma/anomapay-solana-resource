# transfer_circuit

The RISC Zero guest program for the AnomaPay Solana token-transfer resource.

This is its **own Cargo workspace**, excluded from the repository root workspace:
the guest is cross-compiled to the `riscv32im-risc0-zkvm-elf` target and must not
share the host workspace's lockfile or build profile.

## Layout

```
transfer_circuit/
├── src/main.rs            # host binary: reports / dumps the guest ELF + ImageID
└── methods/               # `token-transfer-methods` build crate
    ├── build.rs           # risc0_build::embed_methods()
    └── guest/             # `token-transfer-guest`: the guest program
```

- **`methods`** runs `risc0-build` at compile time to compile the guest and
  generate `TOKEN_TRANSFER_GUEST_ELF` and `TOKEN_TRANSFER_GUEST_ID`.
- **`methods/guest`** is the guest entry point: it reads a
  `TokenTransferWitness`, runs `constrain()` from
  [`transfer_witness`](../transfer_witness), and commits the resulting
  `LogicInstance`. (`borsh` is pinned `<1.6` there so its derive macro stays
  optional and does not break guest cross-compilation.)
- **`src/main.rs`** is a host helper, not the prover: it prints the image ID
  (hex) and ELF size, and with `--dump-elf <path>` writes the guest ELF that
  [`transfer_library`](../transfer_library) embeds.

## Reproducibly building the ELF and ImageID

`ImageID`s differ across machines and environments. To reproduce a publicly
verifiable ELF / `ImageID` that corresponds to this guest source, use the
docker-based reproducible build from the repository root
([RISC Zero toolchain](https://dev.risczero.com) required):

```bash
cargo risczero build --manifest-path transfer_circuit/methods/guest/Cargo.toml
```

To embed a freshly built guest, copy that ELF over
[`transfer_library/elf/token-transfer-guest.bin`](../transfer_library/elf/token-transfer-guest.bin)
and set `TOKEN_TRANSFER_ID` in
[`transfer_library/src/lib.rs`](../transfer_library/src/lib.rs) to the printed
`ImageID`, then record the rotation in
[`transfer_library/VK_HISTORY.md`](../transfer_library/VK_HISTORY.md).
