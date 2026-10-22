# Emergency-migrating logic verifying-key history

The `EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID` constant in `src/lib.rs` is the
RISC0 image ID of the emergency-migrating guest. As for the transfer logic
([`transfer_library/VK_HISTORY.md`](../transfer_library/VK_HISTORY.md)),
changing it orphans every persistent resource minted under the prior key unless
a migration path exists, and CI (`scripts/check-vk-history.sh`) refuses a key
that is not recorded below. Rows follow that file's format and process.

| VK | Commit | Date | Reason | Migration plan |
|---|---|---|---|---|
| `1c8e67654296d8282d40c6826ea8c430e58ed35dd04f5c38b15fdb990cb9f363` | `095cfeb` | 2026-10-15 | The port of the EVM ERC20 resource's emergency-migrating logic: the transfer logic with owner signatures under `TokenTransferAuthorizationEmergencyMigrating`, built on the transfer witness with the call `EmergencyMigratingCall { Transfer, Migrate }`, whose migration trigger commits the emergency-migrating SPL token forwarder's migrate call (`anomapay-spl-token-forwarder-client` `ea2f185a`, the merge of anoma/anomapay-spl-token-forwarder#21). Reproducible Docker build (cargo-risczero 3.0.5, builder r0.1.88.0), byte-identical (ELF sha256 `94325a64…`) from two checkouts at different paths. (Transient values `516cf682…` and `66dc8661…` preceded the review cleanups and the re-pin to the merge.) | N/A — first key of this logic; no resource exists under it. |
| `d5f0c74b1704f1debca28cca85b4ec8e40ee18473e2175a636356fa88c82d19f` | `e67e345` | 2026-10-21 | Release 2.0.0-rc.8: the re-pins of `anoma-pa-solana-client` (`a028b79`) and `anomapay-spl-token-forwarder-client` (`54122150`) recorded in `transfer_library/VK_HISTORY.md`; this logic's checks are unchanged, and the new sources and version change the ELF. Reproducible Docker build (cargo-risczero 3.0.5, builder r0.1.88.0), byte-identical (ELF sha256 `32f83d3f…`) from two checkouts at different paths. | N/A — no deployment pins `1c8e6765…`, and no resource exists under it. |
| `65775681ea2514cac7d8646d7fee5c9775bbccd9bfe28d0acf465513a9179bbb` | (this commit) | 2026-10-22 | Release 2.0.0-rc.9: the re-pins of `anoma-pa-solana-client` (`7ed4f3e`) and `anomapay-spl-token-forwarder-client` (`e122e510`) recorded in `transfer_library/VK_HISTORY.md`; this logic's checks are unchanged, and the new sources and version change the ELF. Reproducible Docker build (cargo-risczero 3.0.5, builder r0.1.88.0), byte-identical (ELF sha256 `641f755e…`) from two checkouts at different paths. | N/A — no deployment pins `d5f0c74b…`, and no resource exists under it. |
