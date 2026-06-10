//! The transfer library contains the definition of the resource logics for the simple transfer
//! application.

#[cfg(test)]
mod test;

use anoma_rm_risc0::{Digest, logic_proof::LogicProver, resource::Resource};
use anoma_rm_risc0_gadgets::authority::{AuthoritySignature, AuthorityVerifyingKey};
use hex::FromHex;
use k256::AffinePoint;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use transfer_witness::{
    EncryptionInfo, ForwarderInfo, LabelInfo, TokenTransferWitness, ValueInfo, WrapAuthInfo,
    call_type::CallType,
};

/// The binary program that is executed in the zkvm to generate proofs.
pub const TOKEN_TRANSFER_ELF: &[u8] = include_bytes!("../elf/token-transfer-guest.bin");

lazy_static! {
    /// The identity of the binary that executes the proofs in the zkvm.
    pub static ref TOKEN_TRANSFER_ID: Digest =
        Digest::from_hex("900df4f9d842b092b980e2d1c1d8d99af5813744d5a04aafcbde61da0b100f51")
            .unwrap();
}

/// Holds the transfer resource logic.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TransferLogic {
    pub witness: TokenTransferWitness,
}

impl TransferLogic {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: Resource,
        is_consumed: bool,
        action_tree_root: Digest,
        nf_key: Option<anoma_rm_risc0::nullifier_key::NullifierKey>,
        auth_sig: Option<AuthoritySignature>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info: Option<ForwarderInfo>,
        label_info: Option<LabelInfo>,
        value_info: Option<ValueInfo>,
    ) -> Self {
        Self {
            witness: TokenTransferWitness::new(
                resource,
                is_consumed,
                action_tree_root,
                nf_key,
                auth_sig,
                encryption_info,
                forwarder_info,
                label_info,
                value_info,
            ),
        }
    }

    /// Creates resource logic for consuming a persistent resource.
    pub fn consume_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: anoma_rm_risc0::nullifier_key::NullifierKey,
        auth_pk: AuthorityVerifyingKey,
        encryption_pk: AffinePoint,
        auth_sig: AuthoritySignature,
    ) -> Self {
        let value_info = ValueInfo {
            auth_pk,
            encryption_pk,
        };
        Self::new(
            resource,
            true,
            action_tree_root,
            Some(nf_key),
            Some(auth_sig),
            None,
            None,
            None,
            Some(value_info),
        )
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
        let encryption_info = EncryptionInfo::new(discovery_pk);
        let label_info = LabelInfo {
            forwarder_program_id,
            spl_token_mint,
        };
        let value_info = ValueInfo {
            auth_pk,
            encryption_pk,
        };
        Self::new(
            resource,
            false,
            action_tree_root,
            None,
            None,
            Some(encryption_info),
            None,
            Some(label_info),
            Some(value_info),
        )
    }

    /// Creates a resource logic for an ephemeral resource created during minting (wrapping SPL tokens).
    #[allow(clippy::too_many_arguments)]
    pub fn mint_resource_logic_with_wrap_auth(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: anoma_rm_risc0::nullifier_key::NullifierKey,
        forwarder_program_id: [u8; 32],
        spl_token_mint: [u8; 32],
        solana_account: [u8; 32],
        nonce: u64,
        deadline: i64,
        ed25519_signature: [u8; 64],
        ed25519_ix_index: u8,
    ) -> Self {
        let wrap_auth_info = WrapAuthInfo {
            nonce,
            deadline,
            ed25519_signature,
            ed25519_ix_index,
        };
        let forwarder_info = ForwarderInfo {
            call_type: CallType::Wrap,
            solana_account: Some(solana_account),
            wrap_auth_info: Some(wrap_auth_info),
        };
        let label_info = LabelInfo {
            forwarder_program_id,
            spl_token_mint,
        };

        Self::new(
            resource,
            true,
            action_tree_root,
            Some(nf_key),
            None,
            None,
            Some(forwarder_info),
            Some(label_info),
            None,
        )
    }

    /// Creates a resource logic for a resource that is created when burning (unwrapping SPL tokens).
    pub fn burn_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        forwarder_program_id: [u8; 32],
        spl_token_mint: [u8; 32],
        recipient_account: [u8; 32],
    ) -> Self {
        let forwarder_info = ForwarderInfo {
            call_type: CallType::Unwrap,
            solana_account: Some(recipient_account),
            wrap_auth_info: None,
        };
        let label_info = LabelInfo {
            forwarder_program_id,
            spl_token_mint,
        };

        Self::new(
            resource,
            false,
            action_tree_root,
            None,
            None,
            None,
            Some(forwarder_info),
            Some(label_info),
            None,
        )
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
