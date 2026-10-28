//! Host-side construction of the AnomaPay wrap and unwrap actions: the
//! resources each flow consumes and creates, and the witnesses that prove it.
//! Each flow is of a logic `L`, the transfer logic or a logic that extends
//! it, whose verifying key its resources carry and whose prover proves them.
//! The caller supplies the keys, the deployment's compliance facts and the
//! prover; a [`TransferAction`] is unproven until [`TransferAction::prove`]
//! or the caller's own prover turns its witnesses into proofs.

use std::marker::PhantomData;

use anoma_rm_risc0::{
    Digest, action,
    action_tree::ActionTree,
    compliance::{ComplianceWitness, INITIAL_ROOT},
    compliance_unit,
    delta_proof::DeltaWitness,
    error::ArmError,
    kind_tree::KindTree,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::{Resource, ResourceWitness, ResourceWitnessConsumed},
    transaction::{self, Delta, Transaction},
};
use anoma_rm_risc0_gadgets::authority::AuthoritySignature;
use anomapay_spl_token_forwarder_client::WrapMessage;
use k256::AffinePoint;
use k256::elliptic_curve::rand_core::CryptoRngCore;
use transfer_witness::{
    LabelInfo, ValueInfo, WrapAuthInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_solana_account, spl_amount_from_quantity,
};

use crate::TransferLogic;

/// The keys a shielded resource's owner holds, as the resource commits to
/// them: the authorization and encryption public keys behind its value
/// reference, and the nullifier key behind its nullifier-key commitment.
#[derive(Clone)]
pub struct Owner {
    pub value: ValueInfo,
    pub nf_key: NullifierKey,
}

impl Owner {
    pub fn value_ref(&self) -> Digest {
        calculate_persistent_value_ref(&self.value)
    }
}

/// The compliance facts the deployment fixes: the commitment randomness of
/// the action's compliance unit and the kind tree the adapter pins, which
/// gives each resource it lists its kind base.
pub struct ComplianceParams<'a> {
    pub rcv: Vec<u8>,
    pub kind_tree: &'a KindTree,
}

/// The user's ed25519 authorization of a wrap, as the forwarder checks it:
/// the Solana account whose tokens are wrapped and whose signature the
/// ed25519 instruction carries, and the terms it signed with the signature.
pub struct WrapAuth {
    pub user: [u8; 32],
    pub info: WrapAuthInfo,
}

/// One AnomaPay action, unproven: the compliance witness over its one
/// consumed and one created resource, and each resource's logic witness,
/// in tag order.
pub struct TransferAction<L = TransferLogic> {
    pub compliance_witness: ComplianceWitness,
    pub consumed_logic: L,
    pub created_logic: L,
}

impl<L: LogicProver> TransferAction<L> {
    /// Proves the action in-process with `proof_type` and wraps it in a
    /// balanced transaction.
    pub fn prove(&self, proof_type: ProofType) -> Result<Transaction, ArmError> {
        let compliance_unit = compliance_unit::create(&self.compliance_witness, proof_type)?;
        let consumed = self.consumed_logic.prove(proof_type)?;
        let created = self.created_logic.prove(proof_type)?;
        let action = action::new(compliance_unit, vec![consumed, created])?;
        let delta_witness = DeltaWitness::from_bytes(&self.compliance_witness.rcv)?;
        transaction::generate_delta_proof(Transaction::create(
            vec![action],
            Delta::Witness(delta_witness),
        ))
    }
}

/// The compliance witness of an action over `resources`, in their order,
/// with each resource's path in the deployment's kind tree.
fn compliance_witness(
    resources: Vec<ResourceWitness>,
    compliance: ComplianceParams<'_>,
) -> ComplianceWitness {
    let kind_paths = compliance.kind_tree.kind_paths_for(&resources);
    ComplianceWitness::from_parts(resources, INITIAL_ROOT, &compliance.rcv, kind_paths)
}

/// An ephemeral resource of the logic `logic_ref` under `label_ref`,
/// nullified by the default key: ephemeral resources hide nothing.
fn ephemeral_resource(
    logic_ref: Digest,
    label_ref: Digest,
    value_ref: Digest,
    quantity: u128,
    nonce: [u8; 32],
) -> Resource {
    Resource {
        logic_ref,
        label_ref,
        value_ref,
        quantity,
        is_ephemeral: true,
        nonce,
        nk_commitment: NullifierKey::default().commit(),
        ..Default::default()
    }
}

/// The action tree root of a one-consumed, one-created action: its
/// resources' tags in the action's order, nullifier then commitment.
fn action_tree_root(consumed_nf: Digest, created: &Resource) -> Result<Digest, ArmError> {
    ActionTree::new(vec![consumed_nf, created.commitment()]).root()
}

/// The resources of an action of the logic `L` that consumes an ephemeral
/// resource under `label` and creates `owner`'s shielded resource of its
/// quantity: a wrap's, or a call of an extending logic that brings a
/// quantity into the shielded pool (the emergency-migrating logic's
/// migration).
pub struct Deposit<L = TransferLogic> {
    pub label: LabelInfo,
    pub owner: Owner,
    pub consumed: Resource,
    pub created: Resource,
    logic: PhantomData<L>,
}

/// The resources of a deposit of `quantity` under `label` for `owner`.
/// `ephemeral_nonce` is the consumed resource's nonce, which its nullifier
/// and therefore the created resource's nonce derive from; `rand_seed` is
/// the created resource's.
pub fn deposit<L: LogicProver>(
    label: LabelInfo,
    quantity: u128,
    ephemeral_nonce: [u8; 32],
    owner: Owner,
    rand_seed: [u8; 32],
) -> Result<Deposit<L>, ArmError> {
    let logic_ref = L::verifying_key();
    let label_ref = calculate_label_ref(&label.forwarder_program_id, &label.spl_token_mint);
    let consumed = ephemeral_resource(
        logic_ref,
        label_ref,
        Digest::default(),
        quantity,
        ephemeral_nonce,
    );
    let created = Resource {
        logic_ref,
        label_ref,
        value_ref: owner.value_ref(),
        quantity,
        is_ephemeral: false,
        nonce: Resource::derive_nonce_from_nullifiers(
            0,
            &[consumed.nullifier(&NullifierKey::default())?],
        )?,
        nk_commitment: owner.nf_key.commit(),
        rand_seed,
    };
    Ok(Deposit {
        label,
        owner,
        consumed,
        created,
        logic: PhantomData,
    })
}

impl<L: LogicProver + From<TransferLogic>> Deposit<L> {
    pub fn action_tree_root(&self) -> Result<Digest, ArmError> {
        action_tree_root(
            self.consumed.nullifier(&NullifierKey::default())?,
            &self.created,
        )
    }

    /// The action's witnesses: the consumed resource's logic is
    /// `consumed_logic` of the action tree root; `discovery_pk` is the key
    /// the created resource's discovery payload is encrypted to, and the
    /// encryption keys and nonces of its payloads are drawn from `rng`.
    pub fn action(
        &self,
        consumed_logic: impl FnOnce(Digest) -> L,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<L>, ArmError> {
        let root = self.action_tree_root()?;
        Ok(TransferAction {
            compliance_witness: compliance_witness(
                vec![
                    ResourceWitness::Consumed(ResourceWitnessConsumed::from_resource(
                        self.consumed,
                        NullifierKey::default(),
                    )),
                    ResourceWitness::Created(self.created),
                ],
                compliance,
            ),
            consumed_logic: consumed_logic(root),
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

/// A wrap: the user deposits `amount` of the label's mint into the
/// forwarder's escrow, consuming an ephemeral resource whose logic commits
/// the forwarder call, and creating the owner's shielded resource.
pub struct Wrap<L = TransferLogic> {
    pub deposit: Deposit<L>,
}

/// The resources of a wrap of `amount` under `label` for `owner`, of the
/// logic `L` (the forwarder's). `ephemeral_nonce` and `rand_seed` are as
/// [`deposit`]'s.
pub fn wrap<L: LogicProver>(
    label: LabelInfo,
    amount: u64,
    ephemeral_nonce: [u8; 32],
    owner: Owner,
    rand_seed: [u8; 32],
) -> Result<Wrap<L>, ArmError> {
    Ok(Wrap {
        deposit: deposit(label, amount as u128, ephemeral_nonce, owner, rand_seed)?,
    })
}

impl<L: LogicProver + From<TransferLogic>> Wrap<L> {
    /// The text the user signs, for the forwarder nonce `nonce` and the
    /// deadline `deadline`, and the ed25519 instruction carries: base64 of
    /// the sha256 of the 120-byte wrap message the forwarder recomputes from
    /// the proof-bound input. The signature goes into the [`WrapAuth`] the
    /// action is built with.
    pub fn signed_message(&self, nonce: u64, deadline: i64) -> Result<String, ArmError> {
        let deposit = &self.deposit;
        Ok(WrapMessage {
            forwarder_id: deposit.label.forwarder_program_id,
            token_mint: deposit.label.spl_token_mint,
            amount: spl_amount_from_quantity(deposit.consumed.quantity)?,
            nonce,
            deadline,
            action_tree_root: deposit.action_tree_root()?.into(),
        }
        .base64_digest())
    }

    /// The action's witnesses, `discovery_pk` and `rng` as
    /// [`Deposit::action`]'s.
    pub fn action(
        &self,
        auth: WrapAuth,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<L>, ArmError> {
        let deposit = &self.deposit;
        deposit.action(
            |root| {
                TransferLogic::mint_resource_logic_with_wrap_auth(
                    deposit.consumed,
                    root,
                    NullifierKey::default(),
                    deposit.label.clone(),
                    auth.user,
                    auth.info,
                )
                .into()
            },
            discovery_pk,
            compliance,
            rng,
        )
    }
}

/// An unwrap: the owner spends a shielded resource into an ephemeral one
/// whose logic commits the forwarder call releasing the escrowed tokens to
/// `recipient`.
pub struct Unwrap<L = TransferLogic> {
    pub label: LabelInfo,
    pub owner: Owner,
    pub recipient: [u8; 32],
    pub consumed: Resource,
    pub created: Resource,
    logic: PhantomData<L>,
}

/// The resources of an unwrap of `wrapped`, `owner`'s shielded resource of
/// the logic `L` under `label`, to the Solana account `recipient`.
pub fn unwrap<L: LogicProver>(
    label: LabelInfo,
    wrapped: Resource,
    owner: Owner,
    recipient: [u8; 32],
) -> Result<Unwrap<L>, ArmError> {
    if wrapped.logic_ref != L::verifying_key() {
        return Err(ArmError::ProveFailed(
            "The unwrapped resource is not of the unwrap's logic".to_string(),
        ));
    }
    let created = ephemeral_resource(
        wrapped.logic_ref,
        wrapped.label_ref,
        calculate_value_ref_from_solana_account(&recipient),
        wrapped.quantity,
        Resource::derive_nonce_from_nullifiers(0, &[wrapped.nullifier(&owner.nf_key)?])?,
    );
    Ok(Unwrap {
        label,
        owner,
        recipient,
        consumed: wrapped,
        created,
        logic: PhantomData,
    })
}

impl<L: LogicProver + From<TransferLogic>> Unwrap<L> {
    /// What the owner signs under the logic's domain.
    pub fn action_tree_root(&self) -> Result<Digest, ArmError> {
        action_tree_root(self.consumed.nullifier(&self.owner.nf_key)?, &self.created)
    }

    /// The action's witnesses. `auth_sig` is the owner's signature over the
    /// action tree root; `cm_merkle_path` is the wrapped resource's path in
    /// the adapter's commitment tree.
    pub fn action(
        &self,
        auth_sig: AuthoritySignature,
        cm_merkle_path: MerklePath,
        compliance: ComplianceParams<'_>,
    ) -> Result<TransferAction<L>, ArmError> {
        let root = self.action_tree_root()?;
        Ok(TransferAction {
            compliance_witness: compliance_witness(
                vec![
                    ResourceWitness::Consumed(ResourceWitnessConsumed::from_resource_with_path(
                        self.consumed,
                        self.owner.nf_key.clone(),
                        cm_merkle_path,
                    )),
                    ResourceWitness::Created(self.created),
                ],
                compliance,
            ),
            consumed_logic: TransferLogic::consume_persistent_resource_logic(
                self.consumed,
                root,
                self.owner.nf_key.clone(),
                self.owner.value.clone(),
                auth_sig,
            )
            .into(),
            created_logic: TransferLogic::burn_resource_logic(
                self.created,
                root,
                self.label.clone(),
                self.recipient,
            )
            .into(),
        })
    }
}
