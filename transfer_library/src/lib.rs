//! The transfer library contains the definition of the resource logics for
//! the AnomaPay token-transfer resource.
//!
//! Of particular interest are the `TransferLogic` struct and the
//! `TokenTransferWitness` it wraps.

#[cfg(test)]
mod test;

use anoma_rm_risc0::{
    Digest, logic_proof::LogicProver, nullifier_key::NullifierKey, resource::Resource,
};
use anoma_rm_risc0_gadgets::authority::{AuthoritySignature, AuthorityVerifyingKey};
use hex::FromHex;
use k256::AffinePoint;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use transfer_witness::{
    EncryptionInfo, ForwarderInfo, LabelInfo, TokenTransferWitness, ValueInfo, WrapAuthInfo,
    call_type::CallType,
};

/// The binary program that is executed in the zkvm to generate proofs.
/// This program takes in a witness as argument and runs the constraint function on it.
pub const TOKEN_TRANSFER_ELF: &[u8] = include_bytes!("../elf/token-transfer-guest.bin");

/// The identity of the binary that executes the proofs in the zkvm.
pub static TOKEN_TRANSFER_ID: LazyLock<Digest> = LazyLock::new(|| {
    Digest::from_hex("6a88d368d3155fa785301807417e2624095732a2622d2bc8eb0f03bf4f6e877c").unwrap()
});

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
        auth_pk: AuthorityVerifyingKey,
        encryption_pk: AffinePoint,
        auth_sig: AuthoritySignature,
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: true,
                action_tree_root,
                nf_key: Some(nf_key),
                auth_sig: Some(auth_sig),
                value_info: Some(ValueInfo {
                    auth_pk,
                    encryption_pk,
                }),
                ..Default::default()
            },
        }
    }

    /// Creates a resource logic for a persistent resource creation.
    pub fn create_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        discovery_pk: &AffinePoint,
        auth_pk: AuthorityVerifyingKey,
        encryption_pk: AffinePoint,
        forwarder_program_id: [u8; 32],
        spl_token_mint: [u8; 32],
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: false,
                action_tree_root,
                encryption_info: Some(EncryptionInfo::new(discovery_pk)),
                label_info: Some(LabelInfo {
                    forwarder_program_id,
                    spl_token_mint,
                }),
                value_info: Some(ValueInfo {
                    auth_pk,
                    encryption_pk,
                }),
                ..Default::default()
            },
        }
    }

    /// Creates a resource logic for the ephemeral resource consumed when
    /// wrapping SPL tokens, authorized by the user's Ed25519 signature in the
    /// settlement transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_resource_logic_with_wrap_auth(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        forwarder_program_id: [u8; 32],
        spl_token_mint: [u8; 32],
        solana_account: [u8; 32],
        nonce: u64,
        deadline: i64,
        ed25519_ix_index: u8,
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: true,
                action_tree_root,
                nf_key: Some(nf_key),
                forwarder_info: Some(ForwarderInfo {
                    call_type: CallType::Wrap,
                    solana_account: Some(solana_account),
                    wrap_auth_info: Some(WrapAuthInfo {
                        nonce,
                        deadline,
                        ed25519_ix_index,
                    }),
                }),
                label_info: Some(LabelInfo {
                    forwarder_program_id,
                    spl_token_mint,
                }),
                ..Default::default()
            },
        }
    }

    /// Creates a resource logic for a resource that is created when burning
    /// (unwrapping SPL tokens) to a recipient Solana account.
    pub fn burn_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        forwarder_program_id: [u8; 32],
        spl_token_mint: [u8; 32],
        recipient_account: [u8; 32],
    ) -> Self {
        Self {
            witness: TokenTransferWitness {
                resource,
                is_consumed: false,
                action_tree_root,
                forwarder_info: Some(ForwarderInfo {
                    call_type: CallType::Unwrap,
                    solana_account: Some(recipient_account),
                    wrap_auth_info: None,
                }),
                label_info: Some(LabelInfo {
                    forwarder_program_id,
                    spl_token_mint,
                }),
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
        *TOKEN_TRANSFER_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}
