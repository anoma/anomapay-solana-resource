# emergency_migrating_transfer_witness

Witness data and resource-logic constraints for the AnomaPay Solana
token-transfer resource's **emergency-migrating logic**, the port of the EVM
ERC20 resource's `anomapay_emergency_migrating_erc20_witness`. It is the
transfer logic of [`transfer_witness`](../transfer_witness) with two changes:

- owners sign under `EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN`
  (`TokenTransferAuthorizationEmergencyMigrating`), so a signature for the
  transfer logic does not authorize this one;
- an ephemeral resource may trigger a **migration** instead of a wrap or an
  unwrap.

## `EmergencyMigratingTokenTransferWitness`

`TokenTransferWitness<EmergencyMigratingCall>`: the transfer logic's witness,
whose ephemeral resources trigger

```rust
pub enum EmergencyMigratingCall {
    Transfer(ForwarderInfo),   // a wrap or an unwrap, checked as the transfer logic checks it
    Migrate(MigrateInfo),      // a migration
}
```

as the EVM resource's `EmergencyMigratingCallType` does.

## Migration

`MigrateInfo { auth_sig, entries }` names the batch a consumed ephemeral
trigger migrates; each `MigrateEntry { resource, nf_key, path, value_info,
forwarder_program_id }` is one resource of a vulnerable logic. The logic
checks that:

- the trigger is consumed and labelled with the forwarder and mint;
- the batch is not empty, and every entry is persistent, has the keys its
  `value_ref` commits to, has the batch's one `auth_pk`, and is labelled with
  its `forwarder_program_id` and the trigger's mint;
- the entries' quantities sum to the trigger's, within an SPL amount;
- `auth_sig` is the owner's signature over the action tree root.

It commits the forwarder's migrate call (`wire::encode_migrate_forwarder_input`,
which `emergency_migrating_transfer_library`'s tests check against
`anomapay-spl-token-forwarder-client`'s): the mint, the total, and per
entry its nullifier, the commitment-tree root its `path` gives, its logic ref
and its forwarder, over a segment of `forwarder_migrate_num_accounts(n)`
accounts. The emergency-migrating forwarder checks each root and logic ref and
records each nullifier; no tokens move.
