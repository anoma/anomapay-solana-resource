# emergency_migrating_transfer_circuit

The RISC Zero guest program for the AnomaPay Solana token-transfer resource's
emergency-migrating logic: it reads an `EmergencyMigratingTokenTransferWitness`,
runs `constrain()` from
[`emergency_migrating_transfer_witness`](../emergency_migrating_transfer_witness),
and commits the resulting `LogicInstance`.

Like [`transfer_circuit`](../transfer_circuit), it is its **own Cargo package**,
excluded from the repository root workspace, with its own lockfile. The only
supported build is the reproducible one; see
[`transfer_library/BUILDING_THE_VK.md`](../transfer_library/BUILDING_THE_VK.md).
