# Emergency-migrating logic verifying-key history

The `EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID` constant in `src/lib.rs` is the
RISC0 image ID of the emergency-migrating guest. As for the transfer logic
([`transfer_library/VK_HISTORY.md`](../transfer_library/VK_HISTORY.md)),
changing it orphans every persistent resource minted under the prior key unless
a migration path exists, and CI (`scripts/check-vk-history.sh`) refuses a key
that is not recorded below. Rows follow that file's format and process.

| VK | Commit | Date | Reason | Migration plan |
|---|---|---|---|---|
| `66dc8661b9dd555a417180c4938fa993b1c6b54bc2a0e0b9e025068be3a045a7` | (this commit) | 2026-10-15 | The port of the EVM ERC20 resource's emergency-migrating logic: the transfer logic with owner signatures under `TokenTransferAuthorizationEmergencyMigrating`, built on the transfer witness with the call `EmergencyMigratingCall { Transfer, Migrate }`, whose migration trigger commits the emergency-migrating SPL token forwarder's migrate call (`anomapay-spl-token-forwarder-client` `fa031821`, anoma/anomapay-spl-token-forwarder#21). Reproducible Docker build (cargo-risczero 3.0.5, builder r0.1.88.0), byte-identical (ELF sha256 `51b64dab…`) from two checkouts at different paths. | N/A — first key of this logic; no resource exists under it. |
