//! The transfer witness library holds the struct to generate proofs over
//! resource logics for the AnomaPay token-transfer resource on Solana: wrap and
//! unwrap of SPL tokens through the SPL token forwarder, and transfers between
//! shielded owners.
pub mod call_type;

use crate::call_type::{CallType, UNWRAP_SEGMENT_NUM_ACCOUNTS, WRAP_SEGMENT_NUM_ACCOUNTS};
use anoma_pa_solana_client::external_call::{
    OutputMode, SolanaExternalCall, encode_unwrap_forwarder_input, encode_wrap_forwarder_input,
};
pub use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0::{
    Digest,
    error::ArmError,
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, hash_bytes},
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySignature, AuthorityVerifyingKey},
    encryption::{Ciphertext, SecretKey},
};
use k256::AffinePoint;
use k256::elliptic_curve::group::GroupEncoding;
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub const AUTH_SIGNATURE_DOMAIN: &[u8] = b"TokenTransferAuthorizationV2";

pub enum DeletionCriterion {
    Immediately = 0,
    Never = 1,
}

/// The SPL token forwarder returns this byte as return data on success.
/// Must match the forwarder's `RESULT_SUCCESS` constant.
pub const FORWARDER_RESULT_SUCCESS: u8 = 1;

pub fn spl_amount_from_quantity(quantity: u128) -> Result<u64, ArmError> {
    u64::try_from(quantity).map_err(|_| {
        ArmError::ProveFailed(format!("SPL token quantity {quantity} exceeds u64::MAX"))
    })
}

/// The EncryptionInfo struct holds information about the encryption keys for the
/// recipient/sender of a resource in a transaction.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub sender_sk: SecretKey,
    pub encryption_nonce: Vec<u8>,
    pub discovery_ciphertext: Vec<u32>,
}

impl EncryptionInfo {
    pub fn new(discovery_pk: &AffinePoint) -> Self {
        let discovery_sk = SecretKey::random();
        let discovery_ciphertext = Ciphertext::encrypt(&vec![0u8], discovery_pk, &discovery_sk)
            .unwrap()
            .as_words();
        let sender_sk = SecretKey::random();
        let encryption_nonce = {
            let mut nonce = [0u8; 12];
            OsRng
                .try_fill_bytes(&mut nonce)
                .expect("Failed to fill encryption nonce");
            nonce
        };
        Self {
            sender_sk,
            encryption_nonce: encryption_nonce.to_vec(),
            discovery_ciphertext,
        }
    }
}

/// LabelInfo holds information about label plaintext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LabelInfo {
    pub forwarder_program_id: [u8; 32],
    pub spl_token_mint: [u8; 32],
}

/// ValueInfo holds information about value plaintext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueInfo {
    pub auth_pk: AuthorityVerifyingKey,
    pub encryption_pk: AffinePoint,
}

/// WrapAuthInfo names the Ed25519 authorization for wrapping SPL tokens: the
/// nonce and deadline the user signed over, and the index of the ed25519
/// instruction in the settlement transaction that carries the signature. The
/// forwarder verifies that instruction through the instructions sysvar; the
/// signature itself is not part of the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrapAuthInfo {
    pub nonce: u64,
    pub deadline: i64,
    pub ed25519_ix_index: u8,
}

/// The struct encoded in the resource payload for persistent created resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceWithLabel {
    pub resource: Resource,
    pub forwarder_program_id: [u8; 32],
    pub spl_token_mint: [u8; 32],
}

impl ResourceWithLabel {
    pub fn new(
        resource: Resource,
        forwarder_program_id: [u8; 32],
        spl_token_mint: [u8; 32],
    ) -> Self {
        Self {
            resource,
            forwarder_program_id,
            spl_token_mint,
        }
    }
}

/// The TokenTransferWitness holds all the information necessary to generate a
/// proof of the resource logic of a given resource.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TokenTransferWitness {
    /// Resource this witness is about.
    pub resource: Resource,
    /// Is this a consumed or created resource.
    pub is_consumed: bool,
    /// Action tree root.
    pub action_tree_root: Digest,
    /// Nullifier key for the resource.
    pub nf_key: Option<NullifierKey>,
    /// A consumed persistent resource requires an authorization signature.
    pub auth_sig: Option<AuthoritySignature>,
    /// See EncryptionInfo struct.
    pub encryption_info: Option<EncryptionInfo>,
    /// See ForwarderInfo struct.
    pub forwarder_info: Option<ForwarderInfo>,
    /// See LabelInfo struct.
    pub label_info: Option<LabelInfo>,
    /// See ValueInfo struct.
    pub value_info: Option<ValueInfo>,
}

/// ForwarderInfo holds information about the forwarder program being used by a
/// transaction and which call it makes.
#[derive(Clone, Serialize, Deserialize)]
pub struct ForwarderInfo {
    pub call_type: CallType,
    /// The user's token account owner for `Wrap`, the recipient for `Unwrap`.
    pub solana_account: Option<[u8; 32]>,
    /// Ed25519 wrap authorization, present only for `Wrap`.
    pub wrap_auth_info: Option<WrapAuthInfo>,
}

impl TokenTransferWitness {
    /// Create a new transfer witness.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: Resource,
        is_consumed: bool,
        action_tree_root: Digest,
        nf_key: Option<NullifierKey>,
        auth_sig: Option<AuthoritySignature>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info: Option<ForwarderInfo>,
        label_info: Option<LabelInfo>,
        value_info: Option<ValueInfo>,
    ) -> Self {
        Self {
            is_consumed,
            resource,
            action_tree_root,
            nf_key,
            auth_sig,
            encryption_info,
            forwarder_info,
            label_info,
            value_info,
        }
    }

    /// Compute the tag (nullifier for consumed, commitment for created).
    pub fn tag(&self) -> Result<Digest, ArmError> {
        if self.is_consumed {
            let nf_key = self
                .nf_key
                .as_ref()
                .ok_or(ArmError::MissingField("Nullifier key"))?;
            self.resource.nullifier(nf_key)
        } else {
            Ok(self.resource.commitment())
        }
    }

    /// Check the value and return it unwrapped.
    pub fn value(&self) -> Result<&ValueInfo, ArmError> {
        let value_info = self
            .value_info
            .as_ref()
            .ok_or(ArmError::MissingField("Value info"))?;

        if self.resource.value_ref != calculate_persistent_value_ref(value_info) {
            return Err(ArmError::InvalidResourceValueRef);
        }

        Ok(value_info)
    }

    /// Checks on ephemeral resources; returns the external_payload.
    pub fn ephemeral_resource_check(
        &self,
        action_root: &[u8],
    ) -> Result<Vec<ExpirableBlob>, ArmError> {
        let forwarder_info = self
            .forwarder_info
            .as_ref()
            .ok_or(ArmError::MissingField("Forwarder info"))?;

        let label_info = self
            .label_info
            .as_ref()
            .ok_or(ArmError::MissingField("Label info"))?;

        // Check resource label: label = sha2(forwarder_program_id, spl_token_mint)
        let label_ref =
            calculate_label_ref(&label_info.forwarder_program_id, &label_info.spl_token_mint);
        if self.resource.label_ref != label_ref {
            return Err(ArmError::ProveFailed(
                "Invalid resource label_ref".to_string(),
            ));
        }

        let (inputs, num_accounts) = match forwarder_info.call_type {
            CallType::Wrap => {
                if !self.is_consumed {
                    return Err(ArmError::ProveFailed(
                        "Token wraps must be triggered by a consumed resource".to_string(),
                    ));
                }

                let wrap_auth = forwarder_info
                    .wrap_auth_info
                    .as_ref()
                    .ok_or(ArmError::MissingField("Wrap auth info"))?;

                let solana_account = forwarder_info
                    .solana_account
                    .as_ref()
                    .ok_or(ArmError::MissingField("solana_account"))?;
                let amount = spl_amount_from_quantity(self.resource.quantity)?;

                let inputs = encode_wrap_forwarder_input(
                    &label_info.spl_token_mint,
                    amount,
                    solana_account,
                    wrap_auth.nonce,
                    wrap_auth.deadline,
                    action_root,
                    wrap_auth.ed25519_ix_index,
                );
                (inputs, WRAP_SEGMENT_NUM_ACCOUNTS)
            }
            CallType::Unwrap => {
                if self.is_consumed {
                    return Err(ArmError::ProveFailed(
                        "Token unwraps must be triggered by a created resource".to_string(),
                    ));
                }

                // Check resource value_ref commits to the recipient Solana account.
                let solana_account = forwarder_info
                    .solana_account
                    .as_ref()
                    .ok_or(ArmError::MissingField("solana_account"))?;
                let value_ref = calculate_value_ref_from_solana_account(solana_account);
                if self.resource.value_ref != value_ref {
                    return Err(ArmError::ProveFailed(
                        "Invalid resource value_ref".to_string(),
                    ));
                }

                let inputs = encode_unwrap_forwarder_input(
                    &label_info.spl_token_mint,
                    spl_amount_from_quantity(self.resource.quantity)?,
                    solana_account,
                );
                (inputs, UNWRAP_SEGMENT_NUM_ACCOUNTS)
            }
        };

        let call_data = SolanaExternalCall {
            program_id: label_info.forwarder_program_id,
            instruction_data: inputs,
            expected_output: vec![FORWARDER_RESULT_SUCCESS],
            output_mode: OutputMode::ReturnData,
            num_accounts,
        };
        let call_data_expirable_blob = ExpirableBlob {
            blob: bytes_to_words(&call_data.encode()),
            deletion_criterion: DeletionCriterion::Immediately as u32,
        };
        Ok(vec![call_data_expirable_blob])
    }

    /// Check persistent resource consumption.
    pub fn persistent_resource_consumption(&self, action_root: &[u8]) -> Result<(), ArmError> {
        spl_amount_from_quantity(self.resource.quantity)?;

        let auth_sig = self
            .auth_sig
            .as_ref()
            .ok_or(ArmError::MissingField("Auth signature"))?;

        let value_info = self.value()?;

        // Verify the authorization signature.
        if value_info
            .auth_pk
            .verify(AUTH_SIGNATURE_DOMAIN, action_root, auth_sig)
            .is_err()
        {
            return Err(ArmError::InvalidSignature);
        }

        Ok(())
    }

    /// Check persistent resource creation; returns discovery_payload and
    /// resource_payload.
    pub fn persistent_resource_creation(
        &self,
    ) -> Result<(Vec<ExpirableBlob>, Vec<ExpirableBlob>), ArmError> {
        spl_amount_from_quantity(self.resource.quantity)?;

        let label_info = self
            .label_info
            .as_ref()
            .ok_or(ArmError::MissingField("Label info"))?;
        let label_ref =
            calculate_label_ref(&label_info.forwarder_program_id, &label_info.spl_token_mint);

        if self.resource.label_ref != label_ref {
            return Err(ArmError::ProveFailed(
                "Invalid resource label_ref".to_string(),
            ));
        }

        let value_info = self.value()?;

        // Generate resource ciphertext.
        let encryption_info = self
            .encryption_info
            .as_ref()
            .ok_or(ArmError::MissingField("Encryption info"))?;
        let payload_plaintext = bincode::serialize(&ResourceWithLabel {
            resource: self.resource,
            forwarder_program_id: label_info.forwarder_program_id,
            spl_token_mint: label_info.spl_token_mint,
        })
        .map_err(|_| ArmError::InvalidResourceSerialization);
        let ciphertext = Ciphertext::encrypt_with_nonce(
            &payload_plaintext?,
            &value_info.encryption_pk,
            &encryption_info.sender_sk,
            encryption_info
                .encryption_nonce
                .clone()
                .try_into()
                .map_err(|_| ArmError::InvalidEncryptionNonce)?,
        )?;

        // Generate resource_payload.
        let ciphertext_expirable_blob = ExpirableBlob {
            blob: ciphertext.as_words(),
            deletion_criterion: DeletionCriterion::Never as u32,
        };

        // Generate discovery_payload.
        let ciphertext_discovery_blob = ExpirableBlob {
            blob: encryption_info.discovery_ciphertext.clone(),
            deletion_criterion: DeletionCriterion::Never as u32,
        };

        Ok((
            vec![ciphertext_discovery_blob],
            vec![ciphertext_expirable_blob],
        ))
    }
}

impl LogicCircuit for TokenTransferWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        let tag = self.tag()?;
        let root_bytes = self.action_tree_root.as_bytes();

        let (discovery_payload, resource_payload, external_payload) = if self.resource.is_ephemeral
        {
            let external_payload = self.ephemeral_resource_check(root_bytes)?;
            (vec![], vec![], external_payload)
        } else if self.is_consumed {
            self.persistent_resource_consumption(root_bytes)?;
            (vec![], vec![], vec![])
        } else {
            let (discovery_payload, resource_payload) = self.persistent_resource_creation()?;
            (discovery_payload, resource_payload, vec![])
        };

        let app_data = AppData {
            resource_payload,
            discovery_payload,
            external_payload,
            application_payload: vec![],
        };

        Ok(LogicInstance {
            tag,
            is_consumed: self.is_consumed,
            root: self.action_tree_root,
            app_data,
        })
    }
}

/// Calculate the value ref based on an authorization key and an encryption key for a given user.
pub fn calculate_persistent_value_ref(value: &ValueInfo) -> Digest {
    hash_bytes(
        &[
            value.auth_pk.to_bytes(),
            value.encryption_pk.to_bytes().to_vec(),
        ]
        .concat(),
    )
}

/// Create the value_ref for a Solana account pubkey (full 32 bytes, no padding needed).
pub fn calculate_value_ref_from_solana_account(solana_account: &[u8; 32]) -> Digest {
    Digest::from_bytes(*solana_account)
}

/// Calculate the label ref based on the forwarder program and token mint.
pub fn calculate_label_ref(forwarder_program_id: &[u8; 32], spl_token_mint: &[u8; 32]) -> Digest {
    hash_bytes(&[forwarder_program_id.as_slice(), spl_token_mint.as_slice()].concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anoma_pa_solana_client::external_call::{OP_UNWRAP, OP_WRAP};
    use anoma_rm_risc0::utils::words_to_bytes;

    const ABOVE_U64: u128 = u64::MAX as u128 + 1;

    #[test]
    fn spl_amount_from_quantity_rejects_overflow() {
        assert_eq!(
            spl_amount_from_quantity(u64::MAX as u128).unwrap(),
            u64::MAX
        );

        let err = spl_amount_from_quantity(ABOVE_U64).expect_err("overflow must reject");
        assert!(
            err.to_string().contains("exceeds u64::MAX"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wrap_external_call_rejects_quantity_above_u64() {
        let err =
            match wrap_witness(ABOVE_U64).ephemeral_resource_check(Digest::default().as_bytes()) {
                Ok(_) => panic!("wrap witness must reject oversized SPL amount"),
                Err(err) => err,
            };
        assert!(
            err.to_string().contains("exceeds u64::MAX"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unwrap_external_call_rejects_quantity_above_u64() {
        let err = match unwrap_witness(ABOVE_U64)
            .ephemeral_resource_check(Digest::default().as_bytes())
        {
            Ok(_) => panic!("unwrap witness must reject oversized SPL amount"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("exceeds u64::MAX"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wrap_and_unwrap_external_calls_accept_u64_max_exactly() {
        let wrap_call = witness_external_call(wrap_witness(u64::MAX as u128));
        assert_eq!(wrap_call.instruction_data[0], OP_WRAP);
        assert_eq!(
            encoded_forwarder_amount(&wrap_call.instruction_data),
            u64::MAX
        );

        let unwrap_call = witness_external_call(unwrap_witness(u64::MAX as u128));
        assert_eq!(unwrap_call.instruction_data[0], OP_UNWRAP);
        assert_eq!(
            encoded_forwarder_amount(&unwrap_call.instruction_data),
            u64::MAX
        );
    }

    fn wrap_witness(quantity: u128) -> TokenTransferWitness {
        let forwarder_program_id = [0x11; 32];
        let spl_token_mint = [0x22; 32];
        let solana_account = [0x33; 32];

        let mut witness = TokenTransferWitness {
            is_consumed: true,
            forwarder_info: Some(ForwarderInfo {
                call_type: CallType::Wrap,
                solana_account: Some(solana_account),
                wrap_auth_info: Some(WrapAuthInfo {
                    nonce: 7,
                    deadline: 1_800_000_000,
                    ed25519_ix_index: 0,
                }),
            }),
            label_info: Some(LabelInfo {
                forwarder_program_id,
                spl_token_mint,
            }),
            ..Default::default()
        };
        witness.resource.quantity = quantity;
        witness.resource.is_ephemeral = true;
        witness.resource.label_ref = calculate_label_ref(&forwarder_program_id, &spl_token_mint);
        witness
    }

    fn unwrap_witness(quantity: u128) -> TokenTransferWitness {
        let forwarder_program_id = [0x55; 32];
        let spl_token_mint = [0x66; 32];
        let recipient = [0x77; 32];

        let mut witness = TokenTransferWitness {
            is_consumed: false,
            forwarder_info: Some(ForwarderInfo {
                call_type: CallType::Unwrap,
                solana_account: Some(recipient),
                wrap_auth_info: None,
            }),
            label_info: Some(LabelInfo {
                forwarder_program_id,
                spl_token_mint,
            }),
            ..Default::default()
        };
        witness.resource.quantity = quantity;
        witness.resource.is_ephemeral = true;
        witness.resource.label_ref = calculate_label_ref(&forwarder_program_id, &spl_token_mint);
        witness.resource.value_ref = calculate_value_ref_from_solana_account(&recipient);
        witness
    }

    fn witness_external_call(witness: TokenTransferWitness) -> SolanaExternalCall {
        let external_payload = witness
            .ephemeral_resource_check(witness.action_tree_root.as_bytes())
            .expect("configured ephemeral witness should emit an external call");
        assert_eq!(external_payload.len(), 1);

        SolanaExternalCall::decode(words_to_bytes(&external_payload[0].blob))
            .expect("external-call blob should decode")
    }

    fn encoded_forwarder_amount(instruction_data: &[u8]) -> u64 {
        const AMOUNT_OFFSET: usize = 1 + 32;
        u64::from_le_bytes(
            instruction_data[AMOUNT_OFFSET..AMOUNT_OFFSET + 8]
                .try_into()
                .expect("forwarder amount field should be present"),
        )
    }
}
