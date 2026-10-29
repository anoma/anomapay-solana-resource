//! Host-side construction of the AnomaPay wrap and unwrap actions: the
//! resources each flow consumes and creates, and the witnesses that prove it.
//! Each flow is of a logic `L`, the transfer logic or a logic that extends
//! it, whose verifying key its resources carry and whose prover proves them.
//! A flow's `action` builds an action of that flow alone; its `parts` are
//! its resources and their logic, which [`build`] puts into one action with
//! other flows' parts, in the caller's order. The caller supplies the keys,
//! the deployment's compliance facts and the prover; a [`TransferAction`] is
//! unproven until [`TransferAction::prove`] or the caller's own prover turns
//! its witnesses into proofs.

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

/// One AnomaPay action, unproven: the compliance witness over its
/// resources, and each resource's logic witness, in the order of the
/// resources.
pub struct TransferAction<L = TransferLogic> {
    pub compliance_witness: ComplianceWitness,
    pub logic_witnesses: Vec<L>,
}

impl<L: LogicProver> TransferAction<L> {
    /// Proves the action in-process with `proof_type` and wraps it in a
    /// balanced transaction.
    pub fn prove(&self, proof_type: ProofType) -> Result<Transaction, ArmError> {
        let compliance_unit = compliance_unit::create(&self.compliance_witness, proof_type)?;
        let logic_proofs = self
            .logic_witnesses
            .iter()
            .map(|logic| logic.prove(proof_type))
            .collect::<Result<_, _>>()?;
        let action = action::new(compliance_unit, logic_proofs)?;
        let delta_witness = DeltaWitness::from_bytes(&self.compliance_witness.rcv)?;
        transaction::generate_delta_proof(Transaction::create(
            vec![action],
            Delta::Witness(delta_witness),
        ))
    }
}

/// Builds the logic witness of a resource of an action from the resource,
/// as the action holds it, and the action's tree root.
pub type PartLogic<'a, L> = Box<dyn FnOnce(Resource, Digest) -> Result<L, ArmError> + 'a>;

/// A resource of an action that [`build`] puts together, and its logic. A
/// created resource's nonce is the one [`build`] derives.
pub struct Part<'a, L = TransferLogic> {
    pub resource: ResourceWitness,
    pub logic: PartLogic<'a, L>,
}

/// A flow's resources for [`build`]: the one it consumes and the one it
/// creates.
pub struct Parts<'a, L = TransferLogic> {
    pub consumed: Part<'a, L>,
    pub created: Part<'a, L>,
}

/// One action of `parts`, in their order, which is the order of the
/// resources in the compliance instance and the action tree, and the order
/// the adapter runs their forwarder calls in. A created resource's nonce
/// derives from its index among the created resources and from the
/// nullifiers of the consumed ones, both in this order, as the compliance
/// circuit requires; the action's resources are those of its compliance
/// witness.
pub fn build<L>(
    parts: Vec<Part<'_, L>>,
    compliance: ComplianceParams<'_>,
) -> Result<TransferAction<L>, ArmError> {
    let nullifiers = parts
        .iter()
        .filter_map(|part| match &part.resource {
            ResourceWitness::Consumed(consumed) => {
                Some(consumed.resource.nullifier(&consumed.nf_key))
            }
            ResourceWitness::Created(_) => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    let nullifiers_digest = Resource::hash_nullifiers(&nullifiers)?;

    let mut created_index = 0;
    let mut tags = Vec::with_capacity(parts.len());
    let mut resources = Vec::with_capacity(parts.len());
    let mut logics = Vec::with_capacity(parts.len());
    for Part {
        mut resource,
        logic,
    } in parts
    {
        tags.push(match &mut resource {
            ResourceWitness::Consumed(consumed) => consumed.resource.nullifier(&consumed.nf_key)?,
            ResourceWitness::Created(created) => {
                created.nonce = Resource::derive_nonce(created_index, nullifiers_digest);
                created_index += 1;
                created.commitment()
            }
        });
        resources.push(resource);
        logics.push(logic);
    }
    let root = ActionTree::new(tags).root()?;

    let logic_witnesses = resources
        .iter()
        .zip(logics)
        .map(|(resource, logic)| logic(*resource.resource(), root))
        .collect::<Result<_, _>>()?;
    let kind_paths = compliance.kind_tree.kind_paths_for(&resources);
    Ok(TransferAction {
        compliance_witness: ComplianceWitness::from_parts(
            resources,
            INITIAL_ROOT,
            &compliance.rcv,
            kind_paths,
        ),
        logic_witnesses,
    })
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
    /// The tree root of the action of the deposit alone.
    pub fn action_tree_root(&self) -> Result<Digest, ArmError> {
        action_tree_root(
            self.consumed.nullifier(&NullifierKey::default())?,
            &self.created,
        )
    }

    /// The deposit's resources for [`build`]: the consumed resource's logic
    /// is `consumed_logic` of the action tree root; `discovery_pk` is the
    /// key the created resource's discovery payload is encrypted to, and the
    /// encryption keys and nonces of its payloads are drawn from `rng`.
    pub fn parts<'a>(
        &'a self,
        consumed_logic: impl FnOnce(Digest) -> Result<L, ArmError> + 'a,
        discovery_pk: &'a AffinePoint,
        rng: &'a mut impl CryptoRngCore,
    ) -> Parts<'a, L> {
        Parts {
            consumed: Part {
                resource: ResourceWitness::Consumed(ResourceWitnessConsumed::from_resource(
                    self.consumed,
                    NullifierKey::default(),
                )),
                logic: Box::new(move |_, root| consumed_logic(root)),
            },
            created: Part {
                resource: ResourceWitness::Created(self.created),
                logic: Box::new(move |resource, root| {
                    Ok(TransferLogic::create_persistent_resource_logic(
                        resource,
                        root,
                        discovery_pk,
                        self.owner.value.clone(),
                        self.label.clone(),
                        rng,
                    )
                    .into())
                }),
            },
        }
    }

    /// The witnesses of the action of the deposit alone, its arguments as
    /// [`Deposit::parts`]'s.
    pub fn action(
        &self,
        consumed_logic: impl FnOnce(Digest) -> L,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<L>, ArmError> {
        let Parts { consumed, created } =
            self.parts(move |root| Ok(consumed_logic(root)), discovery_pk, rng);
        build(vec![consumed, created], compliance)
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
    /// The text the user signs, for the forwarder nonce `nonce`, the
    /// deadline `deadline` and the tree root `action_tree_root` of the
    /// action the wrap is in, and the ed25519 instruction carries: base64 of
    /// the sha256 of the 120-byte wrap message the forwarder recomputes from
    /// the proof-bound input. The root of the wrap's action alone is
    /// [`Deposit::action_tree_root`]. The signature goes into the
    /// [`WrapAuth`] the action is built with.
    pub fn signed_message(
        &self,
        nonce: u64,
        deadline: i64,
        action_tree_root: Digest,
    ) -> Result<String, ArmError> {
        let deposit = &self.deposit;
        Ok(WrapMessage {
            forwarder_id: deposit.label.forwarder_program_id,
            token_mint: deposit.label.spl_token_mint,
            amount: spl_amount_from_quantity(deposit.consumed.quantity)?,
            nonce,
            deadline,
            action_tree_root: action_tree_root.into(),
        }
        .base64_digest())
    }

    /// The wrap's resources for [`build`]: `auth` is the user's
    /// authorization of the wrap in the action of the given tree root;
    /// `discovery_pk` and `rng` are as [`Deposit::parts`]'s.
    pub fn parts<'a>(
        &'a self,
        auth: impl FnOnce(Digest) -> Result<WrapAuth, ArmError> + 'a,
        discovery_pk: &'a AffinePoint,
        rng: &'a mut impl CryptoRngCore,
    ) -> Parts<'a, L> {
        let deposit = &self.deposit;
        deposit.parts(
            move |root| {
                let auth = auth(root)?;
                Ok(TransferLogic::mint_resource_logic_with_wrap_auth(
                    deposit.consumed,
                    root,
                    NullifierKey::default(),
                    deposit.label.clone(),
                    auth.user,
                    auth.info,
                )
                .into())
            },
            discovery_pk,
            rng,
        )
    }

    /// The witnesses of the action of the wrap alone, `auth` its user's
    /// authorization of that action, and `discovery_pk` and `rng` as
    /// [`Deposit::parts`]'s.
    pub fn action(
        &self,
        auth: WrapAuth,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<L>, ArmError> {
        let Parts { consumed, created } = self.parts(move |_| Ok(auth), discovery_pk, rng);
        build(vec![consumed, created], compliance)
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
    /// The tree root of the action of the unwrap alone, which its owner
    /// signs under the logic's domain.
    pub fn action_tree_root(&self) -> Result<Digest, ArmError> {
        action_tree_root(self.consumed.nullifier(&self.owner.nf_key)?, &self.created)
    }

    /// The unwrap's resources for [`build`]. `auth_sig` is the owner's
    /// signature over the given action tree root under the logic's domain;
    /// `cm_merkle_path` is the wrapped resource's path in the adapter's
    /// commitment tree.
    pub fn parts<'a>(
        &'a self,
        auth_sig: impl FnOnce(Digest) -> AuthoritySignature + 'a,
        cm_merkle_path: MerklePath,
    ) -> Parts<'a, L> {
        Parts {
            consumed: Part {
                resource: ResourceWitness::Consumed(
                    ResourceWitnessConsumed::from_resource_with_path(
                        self.consumed,
                        self.owner.nf_key.clone(),
                        cm_merkle_path,
                    ),
                ),
                logic: Box::new(move |resource, root| {
                    Ok(TransferLogic::consume_persistent_resource_logic(
                        resource,
                        root,
                        self.owner.nf_key.clone(),
                        self.owner.value.clone(),
                        auth_sig(root),
                    )
                    .into())
                }),
            },
            created: Part {
                resource: ResourceWitness::Created(self.created),
                logic: Box::new(move |resource, root| {
                    Ok(TransferLogic::burn_resource_logic(
                        resource,
                        root,
                        self.label.clone(),
                        self.recipient,
                    )
                    .into())
                }),
            },
        }
    }

    /// The witnesses of the action of the unwrap alone, `auth_sig` the
    /// owner's signature over [`Unwrap::action_tree_root`] and
    /// `cm_merkle_path` as [`Unwrap::parts`]'s.
    pub fn action(
        &self,
        auth_sig: AuthoritySignature,
        cm_merkle_path: MerklePath,
        compliance: ComplianceParams<'_>,
    ) -> Result<TransferAction<L>, ArmError> {
        let Parts { consumed, created } = self.parts(move |_| auth_sig, cm_merkle_path);
        build(vec![consumed, created], compliance)
    }
}
