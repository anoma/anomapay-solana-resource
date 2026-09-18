//! Host-side construction of the AnomaPay wrap and unwrap actions: the
//! resources each flow consumes and creates, and the witnesses that prove it.
//! The caller supplies the keys, the deployment's compliance facts and the
//! prover; a [`TransferAction`] is unproven until [`TransferAction::prove`]
//! or the caller's own prover turns its witnesses into proofs.

use anoma_pa_solana_client::wrap_message::WrapMessage;
use anoma_rm_risc0::{
    Digest,
    action_tree::ActionTree,
    compliance::{ComplianceWitness, INITIAL_ROOT, KindTableEntry},
    delta_proof::DeltaWitness,
    error::ArmError,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::{ConsumedResourceWitness, Resource},
    transaction::{Delta, Transaction},
};
use anoma_rm_risc0_gadgets::authority::{AuthoritySignature, AuthorityVerifyingKey};
use k256::AffinePoint;
use transfer_witness::{
    LabelInfo, ValueInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_solana_account,
};

use crate::{TOKEN_TRANSFER_ID, TransferLogic};

/// The keys a shielded resource's owner holds, as the resource commits to
/// them: the authorization and encryption public keys behind its value
/// reference, and the nullifier key behind its nullifier-key commitment.
#[derive(Clone)]
pub struct Owner {
    pub auth_pk: AuthorityVerifyingKey,
    pub encryption_pk: AffinePoint,
    pub nf_key: NullifierKey,
}

impl Owner {
    pub fn value_ref(&self) -> Digest {
        calculate_persistent_value_ref(&ValueInfo {
            auth_pk: self.auth_pk,
            encryption_pk: self.encryption_pk,
        })
    }
}

/// The compliance facts the deployment fixes: the commitment randomness of
/// the action's compliance unit and the kind table the adapter pins.
pub struct ComplianceParams {
    pub rcv: Vec<u8>,
    pub kind_table: Vec<KindTableEntry>,
}

/// The user's ed25519 authorization of a wrap, as the forwarder checks it.
pub struct WrapAuth {
    /// The Solana account whose tokens are wrapped and whose signature the
    /// ed25519 instruction carries.
    pub user: [u8; 32],
    pub nonce: u64,
    pub deadline: i64,
    /// The index of the ed25519 instruction in the settlement transaction.
    pub ed25519_ix_index: u8,
}

/// One AnomaPay action, unproven: the compliance witness over its one
/// consumed and one created resource, and each resource's transfer-logic
/// witness, in tag order.
pub struct TransferAction {
    pub compliance_witness: ComplianceWitness,
    pub consumed_logic: TransferLogic,
    pub created_logic: TransferLogic,
    pub action_tree_root: Digest,
}

impl TransferAction {
    /// Proves the action in-process and wraps it in a balanced transaction.
    pub fn prove(&self, proof_type: ProofType) -> Result<Transaction, ArmError> {
        let compliance_unit =
            anoma_rm_risc0::compliance_unit::create(&self.compliance_witness, proof_type)?;
        let consumed = self.consumed_logic.prove(proof_type)?;
        let created = self.created_logic.prove(proof_type)?;
        let action = anoma_rm_risc0::action::new(compliance_unit, vec![consumed, created])?;
        let delta_witness = DeltaWitness::from_bytes(&self.compliance_witness.rcv)?;
        let tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
        anoma_rm_risc0::transaction::generate_delta_proof(tx)
    }
}

/// The nullifier key of every ephemeral resource: they hide nothing, so the
/// default key nullifies them.
pub fn ephemeral_nf_key() -> NullifierKey {
    NullifierKey::default()
}

fn ephemeral_resource(
    label_ref: Digest,
    value_ref: Digest,
    quantity: u128,
    nonce: [u8; 32],
) -> Resource {
    Resource {
        logic_ref: *TOKEN_TRANSFER_ID,
        label_ref,
        value_ref,
        quantity,
        is_ephemeral: true,
        nonce,
        nk_commitment: ephemeral_nf_key().commit(),
        ..Default::default()
    }
}

/// The action tree root of a one-consumed, one-created action: nullifier
/// then commitment, the order the aggregation guest enforces.
fn action_tree_root(consumed_nf: Digest, created_cm: Digest) -> Result<Digest, ArmError> {
    ActionTree::new(vec![consumed_nf, created_cm]).root()
}

fn compliance_witness(
    consumed: Resource,
    nf_key: NullifierKey,
    cm_merkle_path: MerklePath,
    created: Resource,
    params: ComplianceParams,
) -> ComplianceWitness {
    ComplianceWitness::from_parts(
        vec![ConsumedResourceWitness {
            resource: consumed,
            cm_merkle_path,
            nf_key,
        }],
        vec![created],
        INITIAL_ROOT,
        &params.rcv,
        params.kind_table,
    )
}

/// A wrap: the user deposits `amount` of the label's mint into the
/// forwarder's escrow, consuming an ephemeral resource whose logic commits
/// the forwarder call, and creating the owner's shielded resource.
pub struct Wrap {
    pub label: LabelInfo,
    pub consumed: Resource,
    pub consumed_nf: Digest,
    pub created: Resource,
    pub action_tree_root: Digest,
}

/// The resources of a wrap of `amount` under `label`. `ephemeral_nonce` is
/// the consumed resource's nonce, which its nullifier and therefore the
/// created resource's nonce derive from; `rand_seed` is the created
/// resource's.
pub fn wrap(
    label: LabelInfo,
    amount: u64,
    ephemeral_nonce: [u8; 32],
    owner: &Owner,
    rand_seed: [u8; 32],
) -> Result<Wrap, ArmError> {
    let label_ref = calculate_label_ref(&label.forwarder_program_id, &label.spl_token_mint);
    let consumed = ephemeral_resource(
        label_ref,
        Digest::default(),
        amount as u128,
        ephemeral_nonce,
    );
    let consumed_nf = consumed.nullifier(&ephemeral_nf_key())?;
    let created = Resource {
        logic_ref: *TOKEN_TRANSFER_ID,
        label_ref,
        value_ref: owner.value_ref(),
        quantity: amount as u128,
        is_ephemeral: false,
        nonce: Resource::derive_nonce_from_nullifiers(0, &[consumed_nf])?,
        nk_commitment: owner.nf_key.commit(),
        rand_seed,
    };
    let action_tree_root = action_tree_root(consumed_nf, created.commitment())?;
    Ok(Wrap {
        label,
        consumed,
        consumed_nf,
        created,
        action_tree_root,
    })
}

impl Wrap {
    /// The text the user signs and the ed25519 instruction carries: base64
    /// of the sha256 of the 120-byte wrap message the forwarder recomputes
    /// from the proof-bound input.
    pub fn signed_message(&self, auth: &WrapAuth) -> String {
        WrapMessage {
            forwarder_id: self.label.forwarder_program_id,
            token_mint: self.label.spl_token_mint,
            amount: self.consumed.quantity as u64,
            nonce: auth.nonce,
            deadline: auth.deadline,
            action_tree_root: self
                .action_tree_root
                .as_bytes()
                .try_into()
                .expect("a digest is 32 bytes"),
        }
        .base64_digest()
    }

    /// The action's witnesses. `discovery_pk` is the key the created
    /// resource's discovery payload is encrypted to.
    pub fn action(
        &self,
        auth: &WrapAuth,
        owner: &Owner,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams,
    ) -> TransferAction {
        let consumed_logic = TransferLogic::mint_resource_logic_with_wrap_auth(
            self.consumed,
            self.action_tree_root,
            ephemeral_nf_key(),
            self.label.forwarder_program_id,
            self.label.spl_token_mint,
            auth.user,
            auth.nonce,
            auth.deadline,
            auth.ed25519_ix_index,
        );
        let created_logic = TransferLogic::create_persistent_resource_logic(
            self.created,
            self.action_tree_root,
            discovery_pk,
            owner.auth_pk,
            owner.encryption_pk,
            self.label.forwarder_program_id,
            self.label.spl_token_mint,
        );
        TransferAction {
            compliance_witness: compliance_witness(
                self.consumed,
                ephemeral_nf_key(),
                MerklePath::empty(),
                self.created,
                compliance,
            ),
            consumed_logic,
            created_logic,
            action_tree_root: self.action_tree_root,
        }
    }
}

/// An unwrap: the owner spends a shielded resource into an ephemeral one
/// whose logic commits the forwarder call releasing the escrowed tokens to
/// `recipient`.
pub struct Unwrap {
    pub label: LabelInfo,
    pub recipient: [u8; 32],
    pub consumed: Resource,
    pub consumed_nf: Digest,
    pub created: Resource,
    pub action_tree_root: Digest,
}

/// The resources of an unwrap of `wrapped`, a shielded resource under
/// `label` that `owner_nf_key` nullifies, to the Solana account `recipient`.
pub fn unwrap(
    label: LabelInfo,
    wrapped: Resource,
    owner_nf_key: &NullifierKey,
    recipient: [u8; 32],
) -> Result<Unwrap, ArmError> {
    let consumed_nf = wrapped.nullifier(owner_nf_key)?;
    let created = ephemeral_resource(
        wrapped.label_ref,
        calculate_value_ref_from_solana_account(&recipient),
        wrapped.quantity,
        Resource::derive_nonce_from_nullifiers(0, &[consumed_nf])?,
    );
    let action_tree_root = action_tree_root(consumed_nf, created.commitment())?;
    Ok(Unwrap {
        label,
        recipient,
        consumed: wrapped,
        consumed_nf,
        created,
        action_tree_root,
    })
}

impl Unwrap {
    /// The action's witnesses. `auth_sig` is the owner's signature over the
    /// action tree root under `AUTH_SIGNATURE_DOMAIN`; `cm_merkle_path` is
    /// the wrapped resource's path in the adapter's commitment tree.
    pub fn action(
        &self,
        owner: &Owner,
        auth_sig: AuthoritySignature,
        cm_merkle_path: MerklePath,
        compliance: ComplianceParams,
    ) -> TransferAction {
        let consumed_logic = TransferLogic::consume_persistent_resource_logic(
            self.consumed,
            self.action_tree_root,
            owner.nf_key.clone(),
            owner.auth_pk,
            owner.encryption_pk,
            auth_sig,
        );
        let created_logic = TransferLogic::burn_resource_logic(
            self.created,
            self.action_tree_root,
            self.label.forwarder_program_id,
            self.label.spl_token_mint,
            self.recipient,
        );
        TransferAction {
            compliance_witness: compliance_witness(
                self.consumed,
                owner.nf_key.clone(),
                cm_merkle_path,
                self.created,
                compliance,
            ),
            consumed_logic,
            created_logic,
            action_tree_root: self.action_tree_root,
        }
    }
}
