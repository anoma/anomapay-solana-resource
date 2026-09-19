//! The transfer library contains the definition of the resource logics for
//! the AnomaPay token-transfer resource.
//!
//! Of particular interest are the `TransferLogic` struct and the
//! `TokenTransferWitness` it wraps, and the [`action`] module that builds the
//! wrap and unwrap actions from resources and keys.

pub mod action;
#[cfg(test)]
mod test;

use anoma_rm_risc0::{
    Digest, logic_proof::LogicProver, nullifier_key::NullifierKey, resource::Resource,
};
use anoma_rm_risc0_gadgets::authority::AuthoritySignature;
use hex_literal::hex;
use k256::AffinePoint;
use serde::{Deserialize, Serialize};

use transfer_witness::{
    CallType, EncryptionInfo, ForwarderInfo, LabelInfo, TokenTransferWitness, ValueInfo,
    WrapAuthInfo,
};

/// The binary program that is executed in the zkvm to generate proofs.
/// This program takes in a witness as argument and runs the constraint function on it.
pub const TOKEN_TRANSFER_ELF: &[u8] = include_bytes!("../elf/token-transfer-guest.bin");

/// The identity of the binary that executes the proofs in the zkvm.
pub const TOKEN_TRANSFER_ID: Digest = Digest::from_bytes(hex!(
    "725520e56ee1d2e6ec444788a87fd97aae15a9332386fdc360260345136a010b"
));

/// Holds the transfer resource logic.
/// The witness is the input to create a proof, so a `TransferLogic` can be used
/// to generate a proof that the resource logics held within it are correct.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TransferLogic {
    pub witness: TokenTransferWitness,
}

impl TransferLogic {
    /// Creates resource logic for consuming a persistent resource.
    pub fn consume_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        value: ValueInfo,
        auth_sig: AuthoritySignature,
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: true,
                action_tree_root,
                nf_key: Some(nf_key),
                auth_sig: Some(auth_sig),
                value_info: Some(value),
                ..Default::default()
            },
        }
    }

    /// Creates a resource logic for a persistent resource creation.
    pub fn create_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        discovery_pk: &AffinePoint,
        value: ValueInfo,
        label: LabelInfo,
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: false,
                action_tree_root,
                encryption_info: Some(EncryptionInfo::new(discovery_pk)),
                label_info: Some(label),
                value_info: Some(value),
                ..Default::default()
            },
        }
    }

    /// Creates a resource logic for the ephemeral resource consumed when
    /// wrapping SPL tokens, authorized by the user's Ed25519 signature in the
    /// settlement transaction.
    pub fn mint_resource_logic_with_wrap_auth(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        label: LabelInfo,
        user: [u8; 32],
        wrap_auth: WrapAuthInfo,
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: true,
                action_tree_root,
                nf_key: Some(nf_key),
                forwarder_info: Some(ForwarderInfo {
                    call_type: CallType::Wrap,
                    solana_account: user,
                    wrap_auth_info: Some(wrap_auth),
                }),
                label_info: Some(label),
                ..Default::default()
            },
        }
    }

    /// Creates a resource logic for a resource that is created when burning
    /// (unwrapping SPL tokens) to a recipient Solana account.
    pub fn burn_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        label: LabelInfo,
        recipient: [u8; 32],
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: false,
                action_tree_root,
                forwarder_info: Some(ForwarderInfo {
                    call_type: CallType::Unwrap,
                    solana_account: recipient,
                    wrap_auth_info: None,
                }),
                label_info: Some(label),
                ..Default::default()
            },
        }
    }
}

impl LogicProver for TransferLogic {
    type Witness = TokenTransferWitness;
    fn proving_key() -> &'static [u8] {
        TOKEN_TRANSFER_ELF
    }

    fn verifying_key() -> Digest {
        TOKEN_TRANSFER_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}
