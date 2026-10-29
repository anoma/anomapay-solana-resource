//! Host-side construction of a migration, as the EVM resource's
//! `construct_migrate_tx` builds one: the ephemeral trigger it consumes, the
//! owner's resource of this logic it creates, and the witnesses that prove
//! it, unproven until [`TransferAction::prove`] or the caller's own prover
//! turns them into proofs.

use anoma_rm_risc0::{error::ArmError, nullifier_key::NullifierKey};
use anoma_rm_risc0_gadgets::authority::AuthoritySignature;
use emergency_migrating_transfer_witness::{MigrateEntry, total_quantity};
use k256::AffinePoint;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use transfer_library::action::{ComplianceParams, Deposit, Owner, TransferAction, deposit};
use transfer_witness::LabelInfo;

use crate::EmergencyMigratingTransferLogic;

/// A migration: the resources of `entries`, all of one owner and of the
/// label's mint, become one resource of this logic for the deposit's owner
/// under the deposit's label (the emergency-migrating forwarder). The
/// forwarder records the entries' nullifiers; no tokens move.
pub struct Migrate {
    pub entries: Vec<MigrateEntry>,
    pub deposit: Deposit<EmergencyMigratingTransferLogic>,
}

/// The resources of a migration of `entries` to `owner` under `label`;
/// `ephemeral_nonce` and `rand_seed` are as `transfer_library`'s
/// [`deposit`]'s.
pub fn migrate(
    label: LabelInfo,
    entries: Vec<MigrateEntry>,
    ephemeral_nonce: [u8; 32],
    owner: Owner,
    rand_seed: [u8; 32],
) -> Result<Migrate, ArmError> {
    let quantity = total_quantity(&entries)?;
    Ok(Migrate {
        entries,
        deposit: deposit(label, quantity, ephemeral_nonce, owner, rand_seed),
    })
}

impl Migrate {
    /// The action's witnesses. `auth_sig` is the entries' owner's signature
    /// over the deposit's action tree root under
    /// `EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN`; `discovery_pk` and `rng`
    /// are as [`Deposit::action`]'s.
    pub fn action(
        &self,
        auth_sig: AuthoritySignature,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<EmergencyMigratingTransferLogic>, ArmError> {
        let deposit = &self.deposit;
        deposit.action(
            |root| {
                EmergencyMigratingTransferLogic::migrate_resource_logic(
                    deposit.consumed,
                    root,
                    NullifierKey::default(),
                    deposit.label.clone(),
                    auth_sig,
                    self.entries.clone(),
                )
            },
            discovery_pk,
            compliance,
            rng,
        )
    }
}
