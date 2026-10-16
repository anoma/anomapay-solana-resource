# emergency_migrating_transfer_library

Host-side proving API for the AnomaPay Solana token-transfer resource's
emergency-migrating logic, the port of the EVM ERC20 resource's
`anomapay_emergency_migrating_erc20_library`.

## `EmergencyMigratingTransferLogic`

Wraps an `EmergencyMigratingTokenTransferWitness` and implements ARM's
`LogicProver` with this logic's guest. Every `TransferLogic` flow converts
into it (`From<TransferLogic>`), so `transfer_library`'s builders build this
logic's wraps and unwraps (`wrap::<EmergencyMigratingTransferLogic>(..)`); a
consumed persistent resource's signature is then under
`EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN`.
`migrate_resource_logic` builds a migration's trigger.

## Actions

`action::migrate` builds a migration from the entries and the new owner: the
ephemeral trigger it consumes and the owner's resource of this logic it
creates, holding the batch's total (a `transfer_library` `Deposit`).
`Migrate::action` produces a `TransferAction<EmergencyMigratingTransferLogic>`.

## Guest artifacts

`EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF` is the prebuilt guest
(`elf/emergency-migrating-token-transfer-guest.bin`) and
`EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID` its RISC0 image ID. Every change to the
ID is recorded in [`VK_HISTORY.md`](VK_HISTORY.md); the build is
[`transfer_library/BUILDING_THE_VK.md`](../transfer_library/BUILDING_THE_VK.md)'s.
