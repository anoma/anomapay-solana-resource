//! Host-side construction of a migration, as the EVM resource's
//! `construct_migrate_tx` builds one: the ephemeral trigger it consumes, the
//! owner's resource of this logic it creates, and the witnesses that prove
//! it, unproven until the caller's prover turns them into proofs.

use anoma_rm_risc0::{
    Digest,
    error::ArmError,
    nullifier_key::NullifierKey,
    resource::{ConsumedResourceWitness, Resource},
};
use anoma_rm_risc0_gadgets::authority::AuthoritySignature;
use emergency_migrating_transfer_witness::MigrateEntry;
use k256::AffinePoint;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use transfer_library::{
    TransferLogic,
    action::{
        ComplianceParams, Owner, TransferAction, action_tree_root, compliance_witness,
        ephemeral_resource, owned_resource,
    },
};
use transfer_witness::{LabelInfo, calculate_label_ref};

use crate::{EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID, EmergencyMigratingTransferLogic};

/// A migration: the resources of `entries`, all of one owner and of `label`'s
/// mint, become one resource of this logic for `owner` under `label` (the
/// emergency-migrating forwarder). The forwarder records the entries'
/// nullifiers; no tokens move.
pub struct Migrate {
    pub label: LabelInfo,
    pub entries: Vec<MigrateEntry>,
    pub owner: Owner,
    pub consumed: Resource,
    pub created: Resource,
}

/// The resources of a migration of `entries` to `owner` under `label`.
/// `ephemeral_nonce` is the trigger's nonce, which its nullifier and
/// therefore the created resource's nonce derive from; `rand_seed` is the
/// created resource's.
pub fn migrate(
    label: LabelInfo,
    entries: Vec<MigrateEntry>,
    ephemeral_nonce: [u8; 32],
    owner: Owner,
    rand_seed: [u8; 32],
) -> Result<Migrate, ArmError> {
    let quantity = entries
        .iter()
        .try_fold(0u128, |total, entry| {
            total.checked_add(entry.resource.quantity)
        })
        .ok_or_else(|| ArmError::ProveFailed("Migrate quantity overflow".to_string()))?;
    let label_ref = calculate_label_ref(&label.forwarder_program_id, &label.spl_token_mint);
    let consumed = ephemeral_resource(
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID,
        label_ref,
        Digest::default(),
        quantity,
        ephemeral_nonce,
    );
    let created = owned_resource(
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID,
        label_ref,
        &owner,
        quantity,
        consumed.nullifier(&NullifierKey::default())?,
        rand_seed,
    )?;
    Ok(Migrate {
        label,
        entries,
        owner,
        consumed,
        created,
    })
}

impl Migrate {
    /// What the entries' owner signs under
    /// `EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN`.
    pub fn action_tree_root(&self) -> Result<Digest, ArmError> {
        action_tree_root(
            self.consumed.nullifier(&NullifierKey::default())?,
            &self.created,
        )
    }

    /// The action's witnesses. `auth_sig` is the entries' owner's signature
    /// over the action tree root; `discovery_pk` is the key the created
    /// resource's discovery payload is encrypted to, and the encryption keys
    /// and nonces of its payloads are drawn from `rng`.
    pub fn action(
        &self,
        auth_sig: AuthoritySignature,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<EmergencyMigratingTransferLogic>, ArmError> {
        let root = self.action_tree_root()?;
        Ok(TransferAction {
            compliance_witness: compliance_witness(
                ConsumedResourceWitness::from_resource(self.consumed, NullifierKey::default()),
                self.created,
                compliance,
            ),
            consumed_logic: EmergencyMigratingTransferLogic::migrate_resource_logic(
                self.consumed,
                root,
                NullifierKey::default(),
                self.label.clone(),
                auth_sig,
                self.entries.clone(),
            ),
            created_logic: TransferLogic::create_persistent_resource_logic(
                self.created,
                root,
                discovery_pk,
                self.owner.value.clone(),
                self.label.clone(),
                rng,
            )
            .into(),
        })
    }
}
