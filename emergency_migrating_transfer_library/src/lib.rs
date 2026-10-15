//! The emergency-migrating transfer library: the host-side proving API of
//! the token-transfer resource's emergency-migrating logic, as the EVM ERC20
//! resource's `anomapay_emergency_migrating_erc20_library`.
//!
//! `EmergencyMigratingTransferLogic` proves an
//! `EmergencyMigratingTokenTransferWitness` with this logic's guest. The
//! transfer logic's flows convert into it (`From<TransferLogic>`), so
//! `transfer_library`'s builders build this logic's wraps and unwraps
//! (`wrap::<EmergencyMigratingTransferLogic>`), with owner signatures under
//! `EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN`; [`action::migrate`] builds a
//! migration.

pub mod action;
#[cfg(test)]
mod test;

use anoma_rm_risc0::{
    Digest, logic_proof::LogicProver, nullifier_key::NullifierKey, resource::Resource,
};
use anoma_rm_risc0_gadgets::authority::AuthoritySignature;
use emergency_migrating_transfer_witness::{
    EmergencyMigratingCall, EmergencyMigratingTokenTransferWitness, MigrateEntry, MigrateInfo,
};
use hex_literal::hex;
use serde::{Deserialize, Serialize};
use transfer_library::TransferLogic;
use transfer_witness::{LabelInfo, TokenTransferWitness};

/// The binary program that is executed in the zkvm to generate proofs.
/// This program takes in a witness as argument and runs the constraint function on it.
pub const EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF: &[u8] =
    include_bytes!("../elf/emergency-migrating-token-transfer-guest.bin");

/// The identity of the binary that executes the proofs in the zkvm.
pub const EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID: Digest = Digest::from_bytes(hex!(
    "66dc8661b9dd555a417180c4938fa993b1c6b54bc2a0e0b9e025068be3a045a7"
));

/// Holds the emergency-migrating resource logic of one resource.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct EmergencyMigratingTransferLogic {
    pub witness: EmergencyMigratingTokenTransferWitness,
}

/// A transfer-logic flow (consume, create, wrap, unwrap) under this logic. A
/// consumed persistent resource's signature must be under
/// `EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN`.
impl From<TransferLogic> for EmergencyMigratingTransferLogic {
    fn from(logic: TransferLogic) -> Self {
        Self {
            witness: logic.witness.into_call(),
        }
    }
}

impl EmergencyMigratingTransferLogic {
    /// Creates the resource logic of a migration's trigger: the consumed
    /// ephemeral `resource` under `label` (the emergency-migrating
    /// forwarder and the batch's mint), migrating `entries`, which their
    /// owner authorizes with `auth_sig` over the action tree root.
    pub fn migrate_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        label: LabelInfo,
        auth_sig: AuthoritySignature,
        entries: Vec<MigrateEntry>,
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: true,
                action_tree_root,
                nf_key: Some(nf_key),
                forwarder_info: Some(EmergencyMigratingCall::Migrate(MigrateInfo {
                    auth_sig,
                    entries,
                })),
                label_info: Some(label),
                ..Default::default()
            },
        }
    }
}

impl LogicProver for EmergencyMigratingTransferLogic {
    type Witness = EmergencyMigratingTokenTransferWitness;
    fn proving_key() -> &'static [u8] {
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF
    }

    fn verifying_key() -> Digest {
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}
