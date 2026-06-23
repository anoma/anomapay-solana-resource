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
- **`methods/guest`** is the guest entry point: it reads a `TokenTransferWitness`,
  runs `constrain()` from [`transfer_witness`](../transfer_witness), and commits
  the resulting `LogicInstance`. (`borsh` is pinned `<1.6` there so its derive
  macro stays optional and does not break guest cross-compilation.)
- **`src/main.rs`** is a host helper, not the prover: it prints the image ID (hex)
  and ELF size, and with `--dump-elf <path>` writes the guest ELF that
  [`transfer_library`](../transfer_library) embeds. The ELF it dumps is the one
  `risc0-build` compiled locally — convenient for inspection, but **not** a
  reproducible build (see below).

## Reproducibly building the ELF and ImageID

`ImageID`s differ across machines and environments. To reproduce a publicly
verifiable ELF / `ImageID` that corresponds to this guest source, use the
docker-based reproducible build from the repository root
([RISC Zero toolchain](https://dev.risczero.com) required):

```bash
cargo risczero build --manifest-path transfer_circuit/methods/guest/Cargo.toml
```

This prints the `ImageID` and writes the ELF to
`transfer_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/token-transfer-guest.bin`.

To embed a freshly built guest, copy that ELF over
[`transfer_library/elf/token-transfer-guest.bin`](../transfer_library/elf/token-transfer-guest.bin)
and set `TOKEN_TRANSFER_ID` in
[`transfer_library/src/lib.rs`](../transfer_library/src/lib.rs) to the printed
`ImageID`.

> The `risc0-zkvm` `unstable` feature currently needs a patched `cargo-risczero`.
> Until the next RISC Zero release, install it with:
>
> ```bash
> cargo install --force --git https://github.com/risc0/risc0 --tag v3.0.3 -Fexperimental cargo-risczero
> ```

## `ImageID` drift and `TOKEN_TRANSFER_ID`

A fresh `cargo risczero build` will generally produce an `ImageID` that does
**not** equal the `TOKEN_TRANSFER_ID` committed in `transfer_library`. That is
expected: the committed value (and the matching `token-transfer-guest.bin`)
corresponds to a specific historical build, not to a rebuild of the current tree.

The `ImageID` is a digest over the entire compiled guest, which transitively pins
the circuit source, `transfer_witness`, the ARM libraries (`anoma_rm_risc0`,
`anoma_rm_risc0_gadgets`), and the toolchain and every other transitive
dependency. So *any* dependency or toolchain bump re-links the guest and rotates
the `ImageID`, even when the resource-logic behavior is byte-for-byte unchanged.

`TOKEN_TRANSFER_ID` is consumed off-chain (app-level checks) and on-chain (the
deployed Solana protocol adapter and SPL token forwarder). Rotating it is
expensive — it invalidates persistent resources minted under the prior VK and
requires a coordinated upgrade — so it is intentionally **not** bumped on every
rebuild. It changes only when the circuit's proof semantics change.

When you do need to rotate it, follow the process and record the change in
[`transfer_library/VK_HISTORY.md`](../transfer_library/VK_HISTORY.md), which is
the rollback / migration log for every `TOKEN_TRANSFER_ID` value.
