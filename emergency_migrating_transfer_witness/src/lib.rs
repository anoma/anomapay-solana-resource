//! The emergency-migrating transfer witness: the transfer resource's logic
//! (`transfer_witness`) with owner signatures under its own domain, plus the
//! migration of resources of a vulnerable logic, as the EVM ERC20 resource's
//! `anomapay_emergency_migrating_erc20_witness` adds it. A migration consumes
//! an ephemeral resource whose logic proves the batch it migrates (each
//! resource's commitment-tree root, nullifier, logic and forwarder) and
//! commits the emergency-migrating forwarder's migrate call, which records the
//! nullifiers and moves no tokens.
pub use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0::{
    error::ArmError,
    logic_instance::{ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use anoma_rm_risc0_gadgets::authority::AuthoritySignature;
use anomapay_spl_token_forwarder_client::{
    MigrateEntry as ForwarderMigrateEntry, MigrateInput, encode_migrate_forwarder_input,
    forwarder_migrate_num_accounts,
};
use serde::{Deserialize, Serialize};
use transfer_witness::{
    TokenTransferWitness, ValueInfo, calculate_label_ref, calculate_persistent_value_ref,
    external_call_payload, spl_amount_from_quantity,
};

/// The domain owners sign under, the EVM emergency-migrating resource's: a
/// signature for the transfer logic does not authorize this logic.
pub const EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN: &[u8] =
    b"TokenTransferAuthorizationEmergencyMigrating";

/// Everything a proof of one resource's emergency-migrating logic needs: the
/// transfer logic's witness, whose `forwarder_info` names an ephemeral
/// resource's wrap or unwrap, or the migration an ephemeral resource
/// triggers instead.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EmergencyMigratingTokenTransferWitness {
    pub witness: TokenTransferWitness,
    pub migrate_info: Option<MigrateInfo>,
}

/// The batch a migration's trigger migrates.
#[derive(Clone, Serialize, Deserialize)]
pub struct MigrateInfo {
    /// One signature over the action tree root, under
    /// `EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN`, authorizing every entry:
    /// the entries share its key.
    pub auth_sig: AuthoritySignature,
    /// The migrated resources, at least one.
    pub entries: Vec<MigrateEntry>,
}

/// One migrated resource.
#[derive(Clone, Serialize, Deserialize)]
pub struct MigrateEntry {
    pub resource: Resource,
    pub nf_key: NullifierKey,
    /// The resource's path in the adapter's commitment tree; the forwarder
    /// checks the root it gives is one of the adapter's.
    pub path: MerklePath,
    pub value_info: ValueInfo,
    /// The forwarder in the resource's label, which may be another
    /// deployment than the trigger's.
    pub forwarder_program_id: [u8; 32],
}

impl EmergencyMigratingTokenTransferWitness {
    /// Checks on ephemeral resources; returns the external payload: the
    /// transfer logic's wrap or unwrap call, or the migrate call.
    pub fn ephemeral_resource_check(
        &self,
        action_root: &[u8; 32],
    ) -> Result<Vec<ExpirableBlob>, ArmError> {
        match (&self.witness.forwarder_info, &self.migrate_info) {
            (Some(_), None) => self.witness.ephemeral_resource_check(action_root),
            (None, Some(migrate_info)) => self.migration(migrate_info, action_root),
            _ => Err(ArmError::ProveFailed(
                "An ephemeral resource triggers exactly one forwarder call".to_string(),
            )),
        }
    }

    /// The migrate call of the trigger `self` over `migrate_info`'s batch.
    fn migration(
        &self,
        migrate_info: &MigrateInfo,
        action_root: &[u8; 32],
    ) -> Result<Vec<ExpirableBlob>, ArmError> {
        let trigger = &self.witness;
        if !trigger.is_consumed {
            return Err(ArmError::ProveFailed(
                "Token migration must be triggered by a consumed resource".to_string(),
            ));
        }
        let label_info = trigger.label()?;

        let Some(first) = migrate_info.entries.first() else {
            return Err(ArmError::ProveFailed(
                "Migration batch must not be empty".to_string(),
            ));
        };
        let batch_auth_pk = first.value_info.auth_pk;

        let mut total_quantity: u128 = 0;
        let mut entries = Vec::with_capacity(migrate_info.entries.len());
        for entry in &migrate_info.entries {
            if entry.resource.is_ephemeral {
                return Err(ArmError::ProveFailed(
                    "Migrate resource must be non-ephemeral".to_string(),
                ));
            }
            if entry.resource.value_ref != calculate_persistent_value_ref(&entry.value_info) {
                return Err(ArmError::ProveFailed(
                    "Invalid migrate resource value_ref".to_string(),
                ));
            }
            // One signature authorizes the batch, so every entry has its key.
            if entry.value_info.auth_pk != batch_auth_pk {
                return Err(ArmError::ProveFailed(
                    "Migrate batch entries must share the same auth_pk".to_string(),
                ));
            }
            if entry.resource.label_ref
                != calculate_label_ref(&entry.forwarder_program_id, &label_info.spl_token_mint)
            {
                return Err(ArmError::ProveFailed(
                    "Invalid migrate resource label_ref".to_string(),
                ));
            }
            let commitment = entry.resource.commitment();
            let nullifier = entry
                .resource
                .nullifier_from_commitment(&entry.nf_key, &commitment)?;
            total_quantity = total_quantity
                .checked_add(entry.resource.quantity)
                .ok_or_else(|| ArmError::ProveFailed("Migrate quantity overflow".to_string()))?;
            entries.push(ForwarderMigrateEntry {
                nullifier: nullifier.into(),
                commitment_tree_root: entry.path.root(&commitment).into(),
                vulnerable_logic_ref: entry.resource.logic_ref.into(),
                forwarder: entry.forwarder_program_id,
            });
        }

        if total_quantity != trigger.resource.quantity {
            return Err(ArmError::ProveFailed(
                "Wrong total migrate resource quantity".to_string(),
            ));
        }
        if batch_auth_pk
            .verify(
                EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
                action_root,
                &migrate_info.auth_sig,
            )
            .is_err()
        {
            return Err(ArmError::InvalidSignature);
        }

        let num_accounts = forwarder_migrate_num_accounts(entries.len()).ok_or_else(|| {
            ArmError::ProveFailed(format!(
                "A migration of {} entries exceeds the accounts a forwarder call can name",
                entries.len()
            ))
        })?;
        let input = encode_migrate_forwarder_input(&MigrateInput {
            token_mint: label_info.spl_token_mint,
            quantity: spl_amount_from_quantity(total_quantity)?,
            entries,
        });
        Ok(external_call_payload(
            label_info.forwarder_program_id,
            input,
            num_accounts,
        ))
    }
}

impl LogicCircuit for EmergencyMigratingTokenTransferWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        self.witness
            .constrain_with(EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN, |action_root| {
                self.ephemeral_resource_check(action_root)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anoma_pa_solana_client::external_call::SolanaExternalCall;
    use anoma_rm_risc0::{Digest, utils::words_to_bytes};
    use anoma_rm_risc0_gadgets::{
        authority::{AuthoritySigningKey, AuthorityVerifyingKey},
        encryption::random_keypair,
    };
    use transfer_witness::{AUTH_SIGNATURE_DOMAIN, CallType, ForwarderInfo, LabelInfo};

    const FORWARDER_PROGRAM_ID: [u8; 32] = [0x11; 32];
    const LEGACY_FORWARDER_PROGRAM_ID: [u8; 32] = [0x44; 32];
    const SPL_TOKEN_MINT: [u8; 32] = [0x22; 32];
    const VULNERABLE_LOGIC_REF: [u8; 32] = [0x55; 32];
    const ACTION_TREE_ROOT: [u8; 32] = [0x99; 32];

    fn owner_key() -> AuthoritySigningKey {
        AuthoritySigningKey::from_bytes(&[9; 32]).unwrap()
    }

    /// A persistent resource of the vulnerable logic, labelled with
    /// `forwarder`, owned by `auth_sk`.
    fn entry(
        forwarder: [u8; 32],
        quantity: u128,
        seed: u8,
        auth_sk: &AuthoritySigningKey,
    ) -> MigrateEntry {
        let nf_key = NullifierKey::from_bytes([seed; 32]);
        let value_info = ValueInfo {
            auth_pk: AuthorityVerifyingKey::from_signing_key(auth_sk),
            encryption_pk: random_keypair().1,
        };
        MigrateEntry {
            resource: Resource {
                logic_ref: Digest::from_bytes(VULNERABLE_LOGIC_REF),
                label_ref: calculate_label_ref(&forwarder, &SPL_TOKEN_MINT),
                value_ref: calculate_persistent_value_ref(&value_info),
                quantity,
                is_ephemeral: false,
                nk_commitment: nf_key.commit(),
                nonce: [seed; 32],
                ..Default::default()
            },
            nf_key,
            path: MerklePath::from_path(&[(
                Digest::from_bytes([seed; 32]),
                seed.is_multiple_of(2),
            )]),
            value_info,
            forwarder_program_id: forwarder,
        }
    }

    /// The consumed ephemeral resource migrating `entries`, under the
    /// trigger's forwarder, for `quantity`, signed by `auth_sk` under
    /// `domain`.
    fn trigger(
        entries: Vec<MigrateEntry>,
        quantity: u128,
        auth_sk: &AuthoritySigningKey,
        domain: &[u8],
    ) -> EmergencyMigratingTokenTransferWitness {
        EmergencyMigratingTokenTransferWitness {
            witness: TokenTransferWitness {
                resource: Resource {
                    label_ref: calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT),
                    quantity,
                    is_ephemeral: true,
                    nk_commitment: NullifierKey::default().commit(),
                    ..Default::default()
                },
                is_consumed: true,
                action_tree_root: Digest::from_bytes(ACTION_TREE_ROOT),
                nf_key: Some(NullifierKey::default()),
                label_info: Some(LabelInfo {
                    forwarder_program_id: FORWARDER_PROGRAM_ID,
                    spl_token_mint: SPL_TOKEN_MINT,
                }),
                ..Default::default()
            },
            migrate_info: Some(MigrateInfo {
                auth_sig: auth_sk.sign(domain, &ACTION_TREE_ROOT),
                entries,
            }),
        }
    }

    /// A migration of a resource of the legacy forwarder and one of the
    /// trigger's, 60 and 40, signed under the emergency-migrating domain.
    fn migration() -> EmergencyMigratingTokenTransferWitness {
        let owner = owner_key();
        trigger(
            vec![
                entry(LEGACY_FORWARDER_PROGRAM_ID, 60, 1, &owner),
                entry(FORWARDER_PROGRAM_ID, 40, 2, &owner),
            ],
            100,
            &owner,
            EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        )
    }

    fn external_call(witness: &EmergencyMigratingTokenTransferWitness) -> SolanaExternalCall {
        let instance = witness.constrain().expect("the migration proves");
        assert_eq!(instance.app_data.external_payload.len(), 1);
        SolanaExternalCall::decode(words_to_bytes(&instance.app_data.external_payload[0].blob))
            .expect("the external-call blob decodes")
    }

    fn refusal(witness: &EmergencyMigratingTokenTransferWitness) -> String {
        match witness.constrain() {
            Ok(_) => panic!("the logic accepted the witness"),
            Err(err) => err.to_string(),
        }
    }

    fn assert_refuses(witness: &EmergencyMigratingTokenTransferWitness, expected: &str) {
        let err = refusal(witness);
        assert!(err.contains(expected), "expected {expected:?}, got {err:?}");
    }

    fn entries_mut(witness: &mut EmergencyMigratingTokenTransferWitness) -> &mut Vec<MigrateEntry> {
        &mut witness.migrate_info.as_mut().unwrap().entries
    }

    #[test]
    fn auth_signature_domain_is_the_evm_emergency_migrating_resources() {
        assert_eq!(
            EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
            b"TokenTransferAuthorizationEmergencyMigrating"
        );
    }

    /// The trigger commits the forwarder's migrate input for exactly the
    /// batch's nullifiers, roots, logic refs and forwarders, and the
    /// migration segment's account count.
    #[test]
    fn migration_commits_the_forwarder_migrate_call() {
        let witness = migration();
        let call = external_call(&witness);
        let expected_entries = witness
            .migrate_info
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .map(|entry| ForwarderMigrateEntry {
                nullifier: entry.resource.nullifier(&entry.nf_key).unwrap().into(),
                commitment_tree_root: entry.path.root(&entry.resource.commitment()).into(),
                vulnerable_logic_ref: VULNERABLE_LOGIC_REF,
                forwarder: entry.forwarder_program_id,
            });
        assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
        assert_eq!(
            call.num_accounts,
            forwarder_migrate_num_accounts(2).unwrap()
        );
        assert!(call.expected_output.is_empty());
        assert_eq!(
            call.instruction_data,
            encode_migrate_forwarder_input(&MigrateInput {
                token_mint: SPL_TOKEN_MINT,
                quantity: 100,
                entries: expected_entries.collect(),
            })
        );
    }

    #[test]
    fn migration_refuses_a_created_trigger() {
        let mut witness = migration();
        witness.witness.is_consumed = false;
        assert_refuses(&witness, "must be triggered by a consumed resource");
    }

    #[test]
    fn migration_refuses_an_empty_batch() {
        let mut witness = migration();
        entries_mut(&mut witness).clear();
        assert_refuses(&witness, "must not be empty");
    }

    #[test]
    fn migration_refuses_an_ephemeral_entry() {
        let mut witness = migration();
        entries_mut(&mut witness)[1].resource.is_ephemeral = true;
        assert_refuses(&witness, "must be non-ephemeral");
    }

    #[test]
    fn migration_refuses_an_entry_whose_keys_are_not_its_value_ref() {
        let mut witness = migration();
        entries_mut(&mut witness)[1].value_info.encryption_pk = random_keypair().1;
        assert_refuses(&witness, "Invalid migrate resource value_ref");
    }

    #[test]
    fn migration_refuses_entries_of_different_owners() {
        let owner = owner_key();
        let other = AuthoritySigningKey::from_bytes(&[8; 32]).unwrap();
        let witness = trigger(
            vec![
                entry(LEGACY_FORWARDER_PROGRAM_ID, 60, 1, &owner),
                entry(FORWARDER_PROGRAM_ID, 40, 2, &other),
            ],
            100,
            &owner,
            EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        );
        assert_refuses(&witness, "must share the same auth_pk");
    }

    #[test]
    fn migration_refuses_an_entry_of_another_mint() {
        let mut witness = migration();
        entries_mut(&mut witness)[0].resource.label_ref =
            calculate_label_ref(&LEGACY_FORWARDER_PROGRAM_ID, &[0x23; 32]);
        assert_refuses(&witness, "Invalid migrate resource label_ref");
    }

    #[test]
    fn migration_refuses_an_entry_whose_nullifier_key_is_not_its_own() {
        let mut witness = migration();
        entries_mut(&mut witness)[0].nf_key = NullifierKey::from_bytes([7; 32]);
        assert!(witness.constrain().is_err());
    }

    #[test]
    fn migration_refuses_a_trigger_quantity_other_than_the_batchs() {
        let mut witness = migration();
        witness.witness.resource.quantity = 99;
        assert_refuses(&witness, "Wrong total migrate resource quantity");
    }

    #[test]
    fn migration_refuses_a_total_above_u64() {
        let owner = owner_key();
        let witness = trigger(
            vec![
                entry(LEGACY_FORWARDER_PROGRAM_ID, u64::MAX as u128, 1, &owner),
                entry(FORWARDER_PROGRAM_ID, 1, 2, &owner),
            ],
            u64::MAX as u128 + 1,
            &owner,
            EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        );
        assert_refuses(&witness, "exceeds u64::MAX");
    }

    #[test]
    fn migration_refuses_a_signature_under_the_transfer_domain() {
        let owner = owner_key();
        let witness = trigger(
            vec![entry(LEGACY_FORWARDER_PROGRAM_ID, 60, 1, &owner)],
            60,
            &owner,
            AUTH_SIGNATURE_DOMAIN,
        );
        assert!(matches!(
            witness.constrain(),
            Err(ArmError::InvalidSignature)
        ));
    }

    #[test]
    fn migration_refuses_a_batch_whose_segment_exceeds_a_forwarder_call() {
        let owner = owner_key();
        let fits = (1..)
            .take_while(|n| forwarder_migrate_num_accounts(*n).is_some())
            .last()
            .unwrap();
        let entries: Vec<_> = (0..=fits)
            .map(|i| entry(LEGACY_FORWARDER_PROGRAM_ID, 1, i as u8, &owner))
            .collect();
        let quantity = entries.len() as u128;
        let witness = trigger(
            entries,
            quantity,
            &owner,
            EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        );
        assert_refuses(&witness, "exceeds the accounts a forwarder call can name");
    }

    #[test]
    fn an_ephemeral_resource_refuses_both_a_wrap_and_a_migration() {
        let mut witness = migration();
        witness.witness.forwarder_info = Some(ForwarderInfo {
            call_type: CallType::Unwrap,
            solana_account: [0x77; 32],
            wrap_auth_info: None,
        });
        assert_refuses(&witness, "exactly one forwarder call");
    }

    /// The transfer logic's unwrap, through this logic, commits the
    /// transfer logic's call.
    #[test]
    fn an_unwrap_commits_the_transfer_logics_call() {
        let mut witness = migration();
        witness.migrate_info = None;
        witness.witness.is_consumed = false;
        witness.witness.resource.value_ref = Digest::from_bytes([0x77; 32]);
        witness.witness.forwarder_info = Some(ForwarderInfo {
            call_type: CallType::Unwrap,
            solana_account: [0x77; 32],
            wrap_auth_info: None,
        });
        assert_eq!(
            witness
                .constrain()
                .unwrap()
                .app_data
                .external_payload
                .iter()
                .map(|blob| blob.blob.clone())
                .collect::<Vec<_>>(),
            witness
                .witness
                .constrain()
                .unwrap()
                .app_data
                .external_payload
                .iter()
                .map(|blob| blob.blob.clone())
                .collect::<Vec<_>>()
        );
    }

    /// A persistent resource of this logic is spent by its owner's signature
    /// under this logic's domain, and not the transfer logic's.
    #[test]
    fn spending_takes_the_owners_signature_under_this_domain() {
        let owner = owner_key();
        let spent = entry(FORWARDER_PROGRAM_ID, 5, 3, &owner);
        let spend = |domain: &[u8]| EmergencyMigratingTokenTransferWitness {
            witness: TokenTransferWitness {
                resource: spent.resource,
                is_consumed: true,
                action_tree_root: Digest::from_bytes(ACTION_TREE_ROOT),
                nf_key: Some(spent.nf_key.clone()),
                auth_sig: Some(owner.sign(domain, &ACTION_TREE_ROOT)),
                value_info: Some(spent.value_info.clone()),
                ..Default::default()
            },
            migrate_info: None,
        };
        spend(EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN)
            .constrain()
            .expect("the owner's signature under this domain spends");
        assert!(matches!(
            spend(AUTH_SIGNATURE_DOMAIN).constrain(),
            Err(ArmError::InvalidSignature)
        ));
    }
}
