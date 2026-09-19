# transfer_circuit

The RISC Zero guest program for the AnomaPay Solana token-transfer resource:
it reads a `TokenTransferWitness`, runs `constrain()` from
[`transfer_witness`](../transfer_witness), and commits the resulting
`LogicInstance`.

It is its **own Cargo package**, excluded from the repository root workspace:
the guest is cross-compiled to the `riscv32im-risc0-zkvm-elf` target and must
not share the host workspace's lockfile or build profile. (`borsh` is pinned
`<1.6` here so its derive macro stays optional and does not break guest
cross-compilation.)

The only supported build is the reproducible one; see
[`transfer_library/BUILDING_THE_VK.md`](../transfer_library/BUILDING_THE_VK.md).
