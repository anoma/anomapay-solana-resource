//! The v2 transfer witness library holds the struct to generate proofs over
//! resource logics for simple transfer resources in the Anoma Pay application.
//!
//! It mirrors [`transfer_witness`] — same wrap/unwrap logic against the SPL token
//! forwarder — and adds **migration** support for moving a v1 resource to v2. It
//! reuses the v1 building blocks directly (`EncryptionInfo`, `LabelInfo`,
//! `ValueInfo`, `WrapAuthInfo`, `ResourceWithLabel`, the `SolanaExternalCall`
//! wire types, and the `calculate_*` / `spl_amount_from_quantity` helpers), so v2
//! only adds what changes: the forwarder shape and the migration call type.
pub mod call_type_v2;

use crate::call_type_v2::{
    CallTypeV2, MIGRATE_FORWARDER_NUM_ACCOUNTS, encode_migrate_forwarder_input,
    encode_unwrap_forwarder_input, encode_wrap_forwarder_input,
};
pub use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0::{
    Digest,
    error::ArmError,
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    merkle_path::{MerklePath, MerklePathExt},
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::bytes_to_words,
};
use anoma_rm_risc0_gadgets::{authority::AuthoritySignature, encryption::Ciphertext};
use serde::{Deserialize, Serialize};
use transfer_witness::{
    DeletionCriterion, EncryptionInfo, FORWARDER_RESULT_SUCCESS, LabelInfo, OutputMode,
    ResourceWithLabel, SolanaExternalCall, ValueInfo, WrapAuthInfo, calculate_label_ref,
    calculate_persistent_value_ref, calculate_value_ref_from_solana_account,
    spl_amount_from_quantity,
};

pub const AUTH_SIGNATURE_DOMAIN_V2: &[u8] = b"TokenTransferAuthorizationV2";

/// The TokenTransferWitnessV2 holds all the information necessary to generate a
/// proof of the resource logic of a given resource.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TokenTransferWitnessV2 {
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
    /// See ForwarderInfoV2 struct.
    pub forwarder_info_v2: Option<ForwarderInfoV2>,
    /// See LabelInfo struct.
    pub label_info: Option<LabelInfo>,
    /// See ValueInfo struct.
    pub value_info: Option<ValueInfo>,
}

/// ForwarderInfoV2 holds information about the forwarder program being used by a
/// transaction. Unlike v1's `ForwarderInfo`, it supports the `Migrate` call type.
#[derive(Clone, Serialize, Deserialize)]
pub struct ForwarderInfoV2 {
    pub call_type: CallTypeV2,
    /// The recipient/payer Solana account. Not needed for `Migrate`.
    pub solana_account: Option<[u8; 32]>,
    /// Ed25519 wrap authorization, present only for `Wrap`.
    pub wrap_auth_info: Option<WrapAuthInfo>,
    /// Migration data, present only for `Migrate` (moving a v1 resource to v2).
    pub migrate_info: Option<MigrateInfo>,
}

/// MigrateInfo carries the data a `Migrate` call proves about the **v1 resource
/// being migrated**: its resource, nullifier key, a Merkle `path` from the v1
/// commitment tree (proving the resource existed), the owner's authorization
/// signature and `ValueInfo`, and the **v1** forwarder program id used in its
/// label.
#[derive(Clone, Serialize, Deserialize)]
pub struct MigrateInfo {
    pub resource: Resource,
    pub nf_key: NullifierKey,
    /// Merkle path from cm-tree v1 to prove existence of the migrated resource.
    pub path: MerklePath,
    pub auth_sig: AuthoritySignature,
    pub value_info: ValueInfo,
    /// The forwarder program id in the migrated resource label is still the v1 id.
    pub forwarder_program_id: [u8; 32],
}

impl TokenTransferWitnessV2 {
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
            .forwarder_info_v2
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
            CallTypeV2::Wrap => {
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
                    &wrap_auth.ed25519_signature,
                    wrap_auth.ed25519_ix_index,
                );
                (inputs, 12u8)
            }
            CallTypeV2::Unwrap => {
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
                (inputs, 9u8)
            }
            CallTypeV2::Migrate => {
                if !self.is_consumed {
                    return Err(ArmError::ProveFailed(
                        "Token migration must be triggered by a consumed resource".to_string(),
                    ));
                }

                let migrate_info = forwarder_info
                    .migrate_info
                    .as_ref()
                    .ok_or(ArmError::MissingField("Migrate info"))?;

                let amount = spl_amount_from_quantity(self.resource.quantity)?;

                // compute migrate resource commitment tree root
                let migrate_cm = migrate_info.resource.commitment();
                let migrate_root = migrate_info.path.root(&migrate_cm);

                // check migrate_resource is non-ephemeral
                if migrate_info.resource.is_ephemeral {
                    return Err(ArmError::ProveFailed(
                        "Migrate resource must be non-ephemeral".to_string(),
                    ));
                }

                // check migrate_resource authorization
                if migrate_info.resource.value_ref
                    != calculate_persistent_value_ref(&migrate_info.value_info)
                {
                    return Err(ArmError::ProveFailed(
                        "Invalid migrate resource value_ref".to_string(),
                    ));
                }

                if migrate_info
                    .value_info
                    .auth_pk
                    .verify(
                        AUTH_SIGNATURE_DOMAIN_V2,
                        action_root,
                        &migrate_info.auth_sig,
                    )
                    .is_err()
                {
                    return Err(ArmError::InvalidSignature);
                }

                // check migrate_resource quantity
                if migrate_info.resource.quantity != self.resource.quantity {
                    return Err(ArmError::ProveFailed(
                        "Wrong migrate resource quantity".to_string(),
                    ));
                }

                // compute migrate resource nullifier
                let migrate_nf = migrate_info
                    .resource
                    .nullifier_from_commitment(&migrate_info.nf_key, &migrate_cm)?;

                // check migrate_resource label_ref against the v1 forwarder program id
                let migrate_label_ref_v1 = calculate_label_ref(
                    &migrate_info.forwarder_program_id,
                    &label_info.spl_token_mint,
                );
                if migrate_info.resource.label_ref != migrate_label_ref_v1 {
                    return Err(ArmError::ProveFailed(
                        "Invalid migrate resource label_ref".to_string(),
                    ));
                }

                let inputs = encode_migrate_forwarder_input(
                    &label_info.spl_token_mint,
                    amount,
                    migrate_nf.as_bytes(),
                    migrate_root.as_bytes(),
                    migrate_info.resource.logic_ref.as_bytes(),
                    &migrate_info.forwarder_program_id,
                );
                (inputs, MIGRATE_FORWARDER_NUM_ACCOUNTS)
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
            .verify(AUTH_SIGNATURE_DOMAIN_V2, action_root, auth_sig)
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

impl LogicCircuit for TokenTransferWitnessV2 {
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

impl TokenTransferWitnessV2 {
    /// Create a new transfer witness.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: Resource,
        is_consumed: bool,
        action_tree_root: Digest,
        nf_key: Option<NullifierKey>,
        auth_sig: Option<AuthoritySignature>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info_v2: Option<ForwarderInfoV2>,
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
            forwarder_info_v2,
            label_info,
            value_info,
        }
    }
}
