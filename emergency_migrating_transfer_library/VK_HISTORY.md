# Emergency-migrating logic verifying-key history

The `EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID` constant in `src/lib.rs` is the
RISC0 image ID of the emergency-migrating guest. As for the transfer logic
([`transfer_library/VK_HISTORY.md`](../transfer_library/VK_HISTORY.md)),
changing it orphans every persistent resource minted under the prior key unless
a migration path exists, and CI (`scripts/check-vk-history.sh`) refuses a key
that is not recorded below. Rows follow that file's format and process.

| VK | Commit | Date | Reason | Migration plan |
|---|---|---|---|---|
| `516cf6822908a5f95bffaed3f3931f598f6cb1ae95232c1e077c83d148f5267d` | (this commit) | 2026-10-15 | The port of the EVM ERC20 resource's emergency-migrating logic: the transfer logic with owner signatures under `TokenTransferAuthorizationEmergencyMigrating`, plus a migration trigger committing the emergency-migrating SPL token forwarder's migrate call (`anomapay-spl-token-forwarder-client` `fa031821`, anoma/anomapay-spl-token-forwarder#21). Reproducible Docker build (cargo-risczero 3.0.5, builder r0.1.88.0), byte-identical (ELF sha256 `b199d085…`) from two checkouts at different paths. | N/A — first key of this logic; no resource exists under it. |
