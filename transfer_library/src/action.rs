//! Host-side construction of the AnomaPay wrap and unwrap actions: the
//! resources each flow consumes and creates, and the witnesses that prove it.
//! Each flow is of a logic `L`, the transfer logic or a logic that extends
//! it, whose verifying key its resources carry and whose prover proves them.
//!
//! An action is built in two steps. [`Layout::new`] takes the resources of
//! one or several flows in the caller's order and fixes the action: the
//! created resources' nonces, the tags and the action tree root, which the
//! owners and users sign. [`Layout::action`] takes the logic witnesses each
//! flow makes from its laid-out resources and those signatures, and returns
//! the action's witnesses. A flow's `action` method does both for an action
//! of that flow alone. The caller supplies the keys, the deployment's
//! compliance facts and the prover; a [`TransferAction`] is unproven until
//! [`TransferAction::prove`] or the caller's own prover turns its witnesses
//! into proofs.

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

/// An action's resources as the action holds them, in the caller's order,
/// which is the order of the resources in the compliance instance and the
/// action tree, and the order the adapter runs their forwarder calls in;
/// their tags; and the action tree root, which the action's owners and users
/// sign.
#[derive(Clone)]
pub struct Layout {
    resources: Vec<ResourceWitness>,
    tags: Vec<Digest>,
    root: Digest,
}

impl Layout {
    /// The layout of an action of `resources`, in their order. Each created
    /// resource's nonce is set to the one derived from its index among the
    /// created resources and from the nullifiers of the consumed ones, both
    /// in this order, as the compliance circuit requires.
    pub fn new(mut resources: Vec<ResourceWitness>) -> Result<Self, ArmError> {
        let nullifiers = resources
            .iter()
            .filter_map(|resource| match resource {
                ResourceWitness::Consumed(consumed) => {
                    Some(consumed.resource.nullifier(&consumed.nf_key))
                }
                ResourceWitness::Created(_) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;
        let nullifiers_digest = Resource::hash_nullifiers(&nullifiers)?;
        let mut consumed_tags = nullifiers.into_iter();
        let mut created_index = 0;
        let tags = resources
            .iter_mut()
            .map(|resource| match resource {
                ResourceWitness::Consumed(_) => consumed_tags
                    .next()
                    .expect("one nullifier per consumed resource"),
                ResourceWitness::Created(created) => {
                    created.nonce = Resource::derive_nonce(created_index, nullifiers_digest);
                    created_index += 1;
                    created.commitment()
                }
            })
            .collect::<Vec<_>>();
        let root = ActionTree::new(tags.clone()).root()?;
        Ok(Layout {
            resources,
            tags,
            root,
        })
    }

    /// The resources, the created ones with their nonces.
    pub fn resources(&self) -> &[ResourceWitness] {
        &self.resources
    }

    /// The resource at `position`.
    pub fn resource(&self, position: usize) -> Resource {
        *self.resources[position].resource()
    }

    pub fn tags(&self) -> &[Digest] {
        &self.tags
    }

    pub fn root(&self) -> Digest {
        self.root
    }

    /// The action's witnesses: one compliance witness over the laid-out
    /// resources and `logic_witnesses`, one per resource in the layout's
    /// order, each of the resource at its position and of the layout's root.
    pub fn action<L>(
        self,
        logic_witnesses: Vec<L>,
        compliance: ComplianceParams<'_>,
    ) -> Result<TransferAction<L>, ArmError> {
        if logic_witnesses.len() != self.resources.len() {
            return Err(ArmError::LogicVerifierInputCountMismatch {
                expected: self.resources.len(),
                found: logic_witnesses.len(),
            });
        }
        let kind_paths = compliance.kind_tree.kind_paths_for(&self.resources);
        Ok(TransferAction {
            compliance_witness: ComplianceWitness::from_parts(
                self.resources,
                INITIAL_ROOT,
                &compliance.rcv,
                kind_paths,
            ),
            logic_witnesses,
        })
    }
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

/// The resources of an action of the logic `L` that consumes an ephemeral
/// resource under `label` and creates `owner`'s shielded resource of its
/// quantity: a wrap's, or a call of an extending logic that brings a
/// quantity into the shielded pool (the emergency-migrating logic's
/// migration). The created resource's nonce is its [`Layout`]'s.
pub struct Deposit<L = TransferLogic> {
    pub label: LabelInfo,
    pub owner: Owner,
    pub consumed: Resource,
    pub created: Resource,
    logic: PhantomData<L>,
}

/// The resources of a deposit of `quantity` under `label` for `owner`.
/// `ephemeral_nonce` is the consumed resource's nonce; `rand_seed` is the
/// created resource's.
pub fn deposit<L: LogicProver>(
    label: LabelInfo,
    quantity: u128,
    ephemeral_nonce: [u8; 32],
    owner: Owner,
    rand_seed: [u8; 32],
) -> Deposit<L> {
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
        nk_commitment: owner.nf_key.commit(),
        rand_seed,
        ..Default::default()
    };
    Deposit {
        label,
        owner,
        consumed,
        created,
        logic: PhantomData,
    }
}

impl<L: LogicProver + From<TransferLogic>> Deposit<L> {
    /// The deposit's resources for a [`Layout`], consumed then created.
    pub fn resources(&self) -> [ResourceWitness; 2] {
        [
            ResourceWitness::Consumed(ResourceWitnessConsumed::from_resource(
                self.consumed,
                NullifierKey::default(),
            )),
            ResourceWitness::Created(self.created),
        ]
    }

    /// The layout of the action of the deposit alone.
    pub fn layout(&self) -> Result<Layout, ArmError> {
        Layout::new(self.resources().into())
    }

    /// The logic witnesses of the deposit's resources, consumed then
    /// created, in an action of tree root `root` in which the created
    /// resource is laid out as `created`. `consumed_logic` is the consumed
    /// resource's; `discovery_pk` is the key the created resource's discovery
    /// payload is encrypted to, and the encryption keys and nonces of its
    /// payloads are drawn from `rng`.
    pub fn logic_witnesses(
        &self,
        consumed_logic: L,
        created: Resource,
        root: Digest,
        discovery_pk: &AffinePoint,
        rng: &mut impl CryptoRngCore,
    ) -> [L; 2] {
        [
            consumed_logic,
            TransferLogic::create_persistent_resource_logic(
                created,
                root,
                discovery_pk,
                self.owner.value.clone(),
                self.label.clone(),
                rng,
            )
            .into(),
        ]
    }

    /// The witnesses of the action of the deposit alone: the consumed
    /// resource's logic is `consumed_logic` of the action tree root, and
    /// `discovery_pk` and `rng` are as [`Deposit::logic_witnesses`]'s.
    pub fn action(
        &self,
        consumed_logic: impl FnOnce(Digest) -> L,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<L>, ArmError> {
        let layout = self.layout()?;
        let root = layout.root();
        let logic_witnesses = self.logic_witnesses(
            consumed_logic(root),
            layout.resource(1),
            root,
            discovery_pk,
            rng,
        );
        layout.action(logic_witnesses.into(), compliance)
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
) -> Wrap<L> {
    Wrap {
        deposit: deposit(label, amount as u128, ephemeral_nonce, owner, rand_seed),
    }
}

impl<L: LogicProver + From<TransferLogic>> Wrap<L> {
    /// The text the user signs, for the forwarder nonce `nonce`, the
    /// deadline `deadline` and the tree root `action_tree_root` of the
    /// action the wrap is in, and the ed25519 instruction carries: base64 of
    /// the sha256 of the 120-byte wrap message the forwarder recomputes from
    /// the proof-bound input. The signature goes into the [`WrapAuth`] the
    /// wrap's logic witnesses are made with.
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

    /// The logic witnesses of the wrap's resources, consumed then created, in
    /// an action of tree root `root` in which the created resource is laid
    /// out as `created`. `auth` is the user's authorization of the wrap in
    /// that action; `discovery_pk` and `rng` are as
    /// [`Deposit::logic_witnesses`]'s.
    pub fn logic_witnesses(
        &self,
        created: Resource,
        root: Digest,
        auth: WrapAuth,
        discovery_pk: &AffinePoint,
        rng: &mut impl CryptoRngCore,
    ) -> [L; 2] {
        let deposit = &self.deposit;
        deposit.logic_witnesses(
            self.mint_logic(root, auth),
            created,
            root,
            discovery_pk,
            rng,
        )
    }

    /// The witnesses of the action of the wrap alone, `auth` its user's
    /// authorization of that action (over `deposit.layout()`'s root), and
    /// `discovery_pk` and `rng` as [`Deposit::logic_witnesses`]'s.
    pub fn action(
        &self,
        auth: WrapAuth,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<TransferAction<L>, ArmError> {
        self.deposit.action(
            |root| self.mint_logic(root, auth),
            discovery_pk,
            compliance,
            rng,
        )
    }

    /// The logic of the wrap's consumed resource in an action of tree root
    /// `root`.
    fn mint_logic(&self, root: Digest, auth: WrapAuth) -> L {
        let deposit = &self.deposit;
        TransferLogic::mint_resource_logic_with_wrap_auth(
            deposit.consumed,
            root,
            NullifierKey::default(),
            deposit.label.clone(),
            auth.user,
            auth.info,
        )
        .into()
    }
}

/// An unwrap: the owner spends a shielded resource into an ephemeral one
/// whose logic commits the forwarder call releasing the escrowed tokens to
/// `recipient`. The created resource's nonce is its [`Layout`]'s.
pub struct Unwrap<L = TransferLogic> {
    pub label: LabelInfo,
    pub owner: Owner,
    pub recipient: [u8; 32],
    pub consumed: Resource,
    /// The consumed resource's path in the adapter's commitment tree.
    pub cm_merkle_path: MerklePath,
    pub created: Resource,
    logic: PhantomData<L>,
}

/// The resources of an unwrap of `wrapped`, `owner`'s shielded resource of
/// the logic `L` under `label` at `cm_merkle_path` in the adapter's
/// commitment tree, to the Solana account `recipient`.
pub fn unwrap<L: LogicProver>(
    label: LabelInfo,
    wrapped: Resource,
    cm_merkle_path: MerklePath,
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
        [0; 32],
    );
    Ok(Unwrap {
        label,
        owner,
        recipient,
        consumed: wrapped,
        cm_merkle_path,
        created,
        logic: PhantomData,
    })
}

impl<L: LogicProver + From<TransferLogic>> Unwrap<L> {
    /// The unwrap's resources for a [`Layout`], consumed then created.
    pub fn resources(&self) -> [ResourceWitness; 2] {
        [
            ResourceWitness::Consumed(ResourceWitnessConsumed::from_resource_with_path(
                self.consumed,
                self.owner.nf_key.clone(),
                self.cm_merkle_path.clone(),
            )),
            ResourceWitness::Created(self.created),
        ]
    }

    /// The layout of the action of the unwrap alone.
    pub fn layout(&self) -> Result<Layout, ArmError> {
        Layout::new(self.resources().into())
    }

    /// The logic witnesses of the unwrap's resources, consumed then created,
    /// in an action of tree root `root` in which the created resource is laid
    /// out as `created`. `auth_sig` is the owner's signature over `root`
    /// under the logic's domain.
    pub fn logic_witnesses(
        &self,
        created: Resource,
        root: Digest,
        auth_sig: AuthoritySignature,
    ) -> [L; 2] {
        [
            TransferLogic::consume_persistent_resource_logic(
                self.consumed,
                root,
                self.owner.nf_key.clone(),
                self.owner.value.clone(),
                auth_sig,
            )
            .into(),
            TransferLogic::burn_resource_logic(created, root, self.label.clone(), self.recipient)
                .into(),
        ]
    }

    /// The witnesses of the action of the unwrap alone, `auth_sig` the
    /// owner's signature over [`Unwrap::layout`]'s root.
    pub fn action(
        &self,
        auth_sig: AuthoritySignature,
        compliance: ComplianceParams<'_>,
    ) -> Result<TransferAction<L>, ArmError> {
        let layout = self.layout()?;
        let logic_witnesses = self.logic_witnesses(layout.resource(1), layout.root(), auth_sig);
        layout.action(logic_witnesses.into(), compliance)
    }
}
