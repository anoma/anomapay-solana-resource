//! The transfer witness library holds the struct to generate proofs over
//! resource logics for the AnomaPay token-transfer resource on Solana: wrap and
//! unwrap of SPL tokens through the SPL token forwarder, and transfers between
//! shielded owners.
use anoma_pa_solana_client::external_call::{OutputMode, SolanaExternalCall};
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
use anomapay_spl_token_forwarder_client::{
    FORWARDER_UNWRAP_NUM_ACCOUNTS, FORWARDER_WRAP_NUM_ACCOUNTS, WrapInput,
    encode_unwrap_forwarder_input, encode_wrap_forwarder_input,
};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::{AffinePoint, NonZeroScalar};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub const AUTH_SIGNATURE_DOMAIN: &[u8] = b"TokenTransferAuthorization";

pub enum DeletionCriterion {
    Immediately = 0,
    Never = 1,
}

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
    /// Draws the sender keys and nonces from `rng` and encrypts the discovery
    /// payload to `discovery_pk`. The witness is a function of the rng's
    /// output, so a seeded rng reproduces it byte for byte.
    pub fn new(discovery_pk: &AffinePoint, rng: &mut impl CryptoRngCore) -> Self {
        let discovery_sk = random_secret_key(rng);
        let discovery_ciphertext = Ciphertext::encrypt_with_nonce(
            &vec![0u8],
            discovery_pk,
            &discovery_sk,
            random_nonce(rng),
        )
        .unwrap()
        .as_words();
        Self {
            sender_sk: random_secret_key(rng),
            encryption_nonce: random_nonce(rng).to_vec(),
            discovery_ciphertext,
        }
    }
}

/// A uniformly random nonzero scalar as an encryption secret key.
fn random_secret_key(rng: &mut impl CryptoRngCore) -> SecretKey {
    SecretKey::new(*NonZeroScalar::random(rng))
}

/// A random 96-bit AES-GCM nonce.
fn random_nonce(rng: &mut impl CryptoRngCore) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    nonce
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

/// WrapAuthInfo is the user's Ed25519 authorization of an SPL token wrap: the
/// nonce and deadline the user signed over, the signature, and the index of
/// the ed25519 instruction in the settlement transaction that verifies it.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrapAuthInfo {
    pub nonce: u64,
    pub deadline: i64,
    /// The user's signature over the wrap message, committed in the wrap's
    /// forwarder input. The forwarder program does not read it: a program
    /// cannot call the ed25519 verifier, so the ed25519 instruction at
    /// `ed25519_ix_index` verifies it. It is in the input so that the proven
    /// transaction carries it, as the EVM wrap input carries its Permit2
    /// signature, and the submitter builds that instruction from the
    /// transaction alone. Do not remove it as unused.
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
    pub ed25519_ix_index: u8,
}

/// The struct encoded in the resource payload for persistent created resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceWithLabel {
    pub resource: Resource,
    pub forwarder_program_id: [u8; 32],
    pub spl_token_mint: [u8; 32],
}

/// The forwarder call an ephemeral resource of a logic triggers: the
/// transfer logic's [`ForwarderInfo`], or the call of a logic that extends
/// it. The call also fixes the domain the logic's owners sign under, so a
/// signature for one logic does not authorize another.
pub trait ForwarderCall: Clone + Serialize + for<'de> Deserialize<'de> {
    /// The domain a consumed persistent resource's owner signs the action
    /// tree root under.
    const AUTH_SIGNATURE_DOMAIN: &'static [u8];

    /// The external payload of this call, triggered by `resource` (consumed
    /// when `is_consumed`) under its checked `label`.
    fn external_payload(
        &self,
        resource: &Resource,
        is_consumed: bool,
        label: &LabelInfo,
        action_root: &[u8; 32],
    ) -> Result<Vec<ExpirableBlob>, ArmError>;
}

/// The TokenTransferWitness holds all the information necessary to generate a
/// proof of the resource logic of a given resource; `C` is the call an
/// ephemeral resource triggers, which selects the logic.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenTransferWitness<C = ForwarderInfo> {
    pub resource: Resource,
    pub is_consumed: bool,
    pub action_tree_root: Digest,
    /// Present for a consumed resource.
    pub nf_key: Option<NullifierKey>,
    /// A consumed persistent resource requires the owner's signature.
    pub auth_sig: Option<AuthoritySignature>,
    pub encryption_info: Option<EncryptionInfo>,
    pub forwarder_info: Option<C>,
    pub label_info: Option<LabelInfo>,
    pub value_info: Option<ValueInfo>,
}

// Not derived: the derive would require `C: Default`, which a call has no
// meaningful value for.
impl<C> Default for TokenTransferWitness<C> {
    fn default() -> Self {
        Self {
            resource: Resource::default(),
            is_consumed: false,
            action_tree_root: Digest::default(),
            nf_key: None,
            auth_sig: None,
            encryption_info: None,
            forwarder_info: None,
            label_info: None,
            value_info: None,
        }
    }
}

/// The forwarder call an ephemeral resource triggers. The op codes, the
/// input encoders and the account count of each call's CPI segment are
/// owned by the forwarder's own client, `anomapay-spl-token-forwarder-client`,
/// so the circuit and the on-chain forwarder agree byte for byte.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Wrap,
    Unwrap,
}

/// ForwarderInfo holds information about the forwarder program being used by a
/// transaction and which call it makes.
#[derive(Clone, Serialize, Deserialize)]
pub struct ForwarderInfo {
    pub call_type: CallType,
    /// The user's token account owner for `Wrap`, the recipient for `Unwrap`.
    pub solana_account: [u8; 32],
    /// Ed25519 wrap authorization, present only for `Wrap`.
    pub wrap_auth_info: Option<WrapAuthInfo>,
}

impl ForwarderCall for ForwarderInfo {
    const AUTH_SIGNATURE_DOMAIN: &'static [u8] = AUTH_SIGNATURE_DOMAIN;

    fn external_payload(
        &self,
        resource: &Resource,
        is_consumed: bool,
        label: &LabelInfo,
        action_root: &[u8; 32],
    ) -> Result<Vec<ExpirableBlob>, ArmError> {
        let (inputs, num_accounts) = match self.call_type {
            CallType::Wrap => {
                if !is_consumed {
                    return Err(ArmError::ProveFailed(
                        "Token wraps must be triggered by a consumed resource".to_string(),
                    ));
                }

                let wrap_auth = self
                    .wrap_auth_info
                    .as_ref()
                    .ok_or(ArmError::MissingField("Wrap auth info"))?;

                let amount = spl_amount_from_quantity(resource.quantity)?;

                let inputs = encode_wrap_forwarder_input(&WrapInput {
                    token_mint: label.spl_token_mint,
                    amount,
                    user: self.solana_account,
                    nonce: wrap_auth.nonce,
                    deadline: wrap_auth.deadline,
                    action_tree_root: *action_root,
                    signature: wrap_auth.signature,
                    ed25519_ix_index: wrap_auth.ed25519_ix_index,
                });
                (inputs, FORWARDER_WRAP_NUM_ACCOUNTS)
            }
            CallType::Unwrap => {
                if is_consumed {
                    return Err(ArmError::ProveFailed(
                        "Token unwraps must be triggered by a created resource".to_string(),
                    ));
                }

                // Check resource value_ref commits to the recipient Solana account.
                let value_ref = calculate_value_ref_from_solana_account(&self.solana_account);
                if resource.value_ref != value_ref {
                    return Err(ArmError::ProveFailed(
                        "Invalid resource value_ref".to_string(),
                    ));
                }

                let inputs = encode_unwrap_forwarder_input(
                    &label.spl_token_mint,
                    spl_amount_from_quantity(resource.quantity)?,
                    &self.solana_account,
                );
                (inputs, FORWARDER_UNWRAP_NUM_ACCOUNTS)
            }
        };

        Ok(external_call_payload(
            label.forwarder_program_id,
            inputs,
            num_accounts,
        ))
    }
}

impl<C> TokenTransferWitness<C> {
    /// The same witness, with its call taken into a logic that extends this
    /// one (`D: From<C>`).
    pub fn into_call<D: From<C>>(self) -> TokenTransferWitness<D> {
        TokenTransferWitness {
            resource: self.resource,
            is_consumed: self.is_consumed,
            action_tree_root: self.action_tree_root,
            nf_key: self.nf_key,
            auth_sig: self.auth_sig,
            encryption_info: self.encryption_info,
            forwarder_info: self.forwarder_info.map(D::from),
            label_info: self.label_info,
            value_info: self.value_info,
        }
    }
}

impl<C: ForwarderCall> TokenTransferWitness<C> {
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

    /// The resource's label, checked against its label ref:
    /// sha2(forwarder_program_id, spl_token_mint).
    pub fn label(&self) -> Result<&LabelInfo, ArmError> {
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
        Ok(label_info)
    }

    /// Checks on ephemeral resources; returns the external_payload.
    pub fn ephemeral_resource_check(
        &self,
        action_root: &[u8; 32],
    ) -> Result<Vec<ExpirableBlob>, ArmError> {
        let forwarder_info = self
            .forwarder_info
            .as_ref()
            .ok_or(ArmError::MissingField("Forwarder info"))?;
        forwarder_info.external_payload(
            &self.resource,
            self.is_consumed,
            self.label()?,
            action_root,
        )
    }

    /// Check persistent resource consumption: the owner signed the action
    /// tree root under the logic's domain.
    pub fn persistent_resource_consumption(&self, action_root: &[u8; 32]) -> Result<(), ArmError> {
        spl_amount_from_quantity(self.resource.quantity)?;

        let auth_sig = self
            .auth_sig
            .as_ref()
            .ok_or(ArmError::MissingField("Auth signature"))?;

        let value_info = self.value()?;

        if value_info
            .auth_pk
            .verify(C::AUTH_SIGNATURE_DOMAIN, action_root, auth_sig)
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

        let label_info = self.label()?;
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

        let ciphertext_expirable_blob = ExpirableBlob {
            blob: ciphertext.as_words(),
            deletion_criterion: DeletionCriterion::Never as u32,
        };

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

impl<C: ForwarderCall> LogicCircuit for TokenTransferWitness<C> {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        let tag = self.tag()?;
        let root_bytes: [u8; 32] = self.action_tree_root.into();

        let (discovery_payload, resource_payload, external_payload) = if self.resource.is_ephemeral
        {
            let external_payload = self.ephemeral_resource_check(&root_bytes)?;
            (vec![], vec![], external_payload)
        } else if self.is_consumed {
            self.persistent_resource_consumption(&root_bytes)?;
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

/// The external payload of a call of the forwarder `program_id` with
/// `instruction_data` over a segment of `num_accounts` accounts.
pub fn external_call_payload(
    program_id: [u8; 32],
    instruction_data: Vec<u8>,
    num_accounts: u8,
) -> Vec<ExpirableBlob> {
    let call_data = SolanaExternalCall {
        program_id,
        instruction_data,
        // The forwarder returns the empty output, as the EVM ERC20
        // forwarder does, whose resource expects it the same way.
        expected_output: Vec::new(),
        output_mode: OutputMode::ReturnData,
        num_accounts,
    };
    vec![ExpirableBlob {
        blob: bytes_to_words(&call_data.encode()),
        deletion_criterion: DeletionCriterion::Immediately as u32,
    }]
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
    use anoma_rm_risc0::utils::words_to_bytes;
    use anomapay_spl_token_forwarder_client::{OP_UNWRAP, OP_WRAP};

    const FORWARDER_PROGRAM_ID: [u8; 32] = [0x11; 32];
    const SPL_TOKEN_MINT: [u8; 32] = [0x22; 32];
    const USER: [u8; 32] = [0x33; 32];
    const RECIPIENT: [u8; 32] = [0x77; 32];
    const WRAP_NONCE: u64 = 7;
    const WRAP_DEADLINE: i64 = 1_800_000_000;
    const ED25519_IX_INDEX: u8 = 0;
    const WRAP_SIGNATURE: [u8; 64] = [0x5a; 64];
    const ACTION_TREE_ROOT: [u8; 32] = [0x99; 32];
    const ABOVE_U64: u128 = u64::MAX as u128 + 1;

    /// The owner signs under the domain of the EVM V2 transfer resource the
    /// EVM V2 forwarder serves (anoma/anomapay-erc20-resource
    /// `transfer_witness`); the `V2` string is its migration resource's.
    #[test]
    fn auth_signature_domain_is_the_evm_transfer_resources() {
        assert_eq!(AUTH_SIGNATURE_DOMAIN, b"TokenTransferAuthorization");
    }

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
        let err = wrap_witness(ABOVE_U64)
            .ephemeral_resource_check(&ACTION_TREE_ROOT)
            .expect_err("wrap witness must reject oversized SPL amount");
        assert!(
            err.to_string().contains("exceeds u64::MAX"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unwrap_external_call_rejects_quantity_above_u64() {
        let err = unwrap_witness(ABOVE_U64)
            .ephemeral_resource_check(&ACTION_TREE_ROOT)
            .expect_err("unwrap witness must reject oversized SPL amount");
        assert!(
            err.to_string().contains("exceeds u64::MAX"),
            "unexpected error: {err}"
        );
    }

    /// The wrap call commits the V2 forwarder's segment and exactly the
    /// encoder's bytes for every witness value, the action tree root included.
    #[test]
    fn wrap_external_call_commits_the_forwarder_segment() {
        let call = witness_external_call(wrap_witness(u64::MAX as u128));
        assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
        assert_eq!(call.num_accounts, FORWARDER_WRAP_NUM_ACCOUNTS);
        assert!(call.expected_output.is_empty());
        assert_eq!(call.output_mode, OutputMode::ReturnData);
        assert_eq!(call.instruction_data[0], OP_WRAP);
        assert_eq!(
            call.instruction_data,
            encode_wrap_forwarder_input(&WrapInput {
                token_mint: SPL_TOKEN_MINT,
                amount: u64::MAX,
                user: USER,
                nonce: WRAP_NONCE,
                deadline: WRAP_DEADLINE,
                action_tree_root: ACTION_TREE_ROOT,
                signature: WRAP_SIGNATURE,
                ed25519_ix_index: ED25519_IX_INDEX,
            })
        );
    }

    #[test]
    fn unwrap_external_call_commits_the_forwarder_segment() {
        let call = witness_external_call(unwrap_witness(u64::MAX as u128));
        assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
        assert_eq!(call.num_accounts, FORWARDER_UNWRAP_NUM_ACCOUNTS);
        assert!(call.expected_output.is_empty());
        assert_eq!(call.output_mode, OutputMode::ReturnData);
        assert_eq!(call.instruction_data[0], OP_UNWRAP);
        assert_eq!(
            call.instruction_data,
            encode_unwrap_forwarder_input(&SPL_TOKEN_MINT, u64::MAX, &RECIPIENT)
        );
    }

    fn wrap_witness(quantity: u128) -> TokenTransferWitness {
        let mut witness = TokenTransferWitness {
            is_consumed: true,
            forwarder_info: Some(ForwarderInfo {
                call_type: CallType::Wrap,
                solana_account: USER,
                wrap_auth_info: Some(WrapAuthInfo {
                    nonce: WRAP_NONCE,
                    deadline: WRAP_DEADLINE,
                    signature: WRAP_SIGNATURE,
                    ed25519_ix_index: ED25519_IX_INDEX,
                }),
            }),
            label_info: Some(LabelInfo {
                forwarder_program_id: FORWARDER_PROGRAM_ID,
                spl_token_mint: SPL_TOKEN_MINT,
            }),
            ..Default::default()
        };
        witness.resource.quantity = quantity;
        witness.resource.is_ephemeral = true;
        witness.resource.label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT);
        witness
    }

    fn unwrap_witness(quantity: u128) -> TokenTransferWitness {
        let mut witness = TokenTransferWitness {
            is_consumed: false,
            forwarder_info: Some(ForwarderInfo {
                call_type: CallType::Unwrap,
                solana_account: RECIPIENT,
                wrap_auth_info: None,
            }),
            label_info: Some(LabelInfo {
                forwarder_program_id: FORWARDER_PROGRAM_ID,
                spl_token_mint: SPL_TOKEN_MINT,
            }),
            ..Default::default()
        };
        witness.resource.quantity = quantity;
        witness.resource.is_ephemeral = true;
        witness.resource.label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT);
        witness.resource.value_ref = calculate_value_ref_from_solana_account(&RECIPIENT);
        witness
    }

    fn witness_external_call(witness: TokenTransferWitness) -> SolanaExternalCall {
        let external_payload = witness
            .ephemeral_resource_check(&ACTION_TREE_ROOT)
            .expect("configured ephemeral witness should emit an external call");
        assert_eq!(external_payload.len(), 1);

        SolanaExternalCall::decode(words_to_bytes(&external_payload[0].blob))
            .expect("external-call blob should decode")
    }
}
