//! Host-side construction of the AnomaPay wrap and unwrap actions: the
//! resources each flow consumes and creates, and the witnesses that prove it.
//! The caller supplies the keys, the deployment's compliance facts and the
//! prover; a [`TransferAction`] is unproven until the caller's prover turns
//! its witnesses into proofs.

use anoma_pa_solana_client::wrap_message::WrapMessage;
use anoma_rm_risc0::{
    Digest,
    action_tree::ActionTree,
    compliance::{ComplianceWitness, INITIAL_ROOT, KindTableEntry},
    error::ArmError,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::{ConsumedResourceWitness, Resource},
};
use anoma_rm_risc0_gadgets::authority::AuthoritySignature;
use k256::AffinePoint;
use transfer_witness::{
    LabelInfo, ValueInfo, WrapAuthInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_solana_account,
};

use crate::{TOKEN_TRANSFER_ID, TransferLogic};

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
/// the action's compliance unit and the kind table the adapter pins.
pub struct ComplianceParams {
    pub rcv: Vec<u8>,
    pub kind_table: Vec<KindTableEntry>,
}

/// The user's ed25519 authorization of a wrap, as the forwarder checks it:
/// the Solana account whose tokens are wrapped and whose signature the
/// ed25519 instruction carries, and the terms it signed.
pub struct WrapAuth {
    pub user: [u8; 32],
    pub info: WrapAuthInfo,
}

/// One AnomaPay action, unproven: the compliance witness over its one
/// consumed and one created resource, and each resource's transfer-logic
/// witness, in tag order.
pub struct TransferAction {
    pub compliance_witness: ComplianceWitness,
    pub consumed_logic: TransferLogic,
    pub created_logic: TransferLogic,
}

/// An ephemeral resource under `label_ref`, nullified by the default key:
/// ephemeral resources hide nothing.
fn ephemeral_resource(
    label_ref: Digest,
    value_ref: Digest,
    quantity: u128,
    nonce: [u8; 32],
) -> Resource {
    Resource {
        logic_ref: TOKEN_TRANSFER_ID,
        label_ref,
        value_ref,
        quantity,
        is_ephemeral: true,
        nonce,
        nk_commitment: NullifierKey::default().commit(),
        ..Default::default()
    }
}

/// The action tree root of a one-consumed, one-created action: nullifier
/// then commitment, the order the aggregation guest enforces.
fn action_tree_root(consumed_nf: Digest, created: &Resource) -> Result<Digest, ArmError> {
    ActionTree::new(vec![consumed_nf, created.commitment()]).root()
}

/// A wrap: the user deposits `amount` of the label's mint into the
/// forwarder's escrow, consuming an ephemeral resource whose logic commits
/// the forwarder call, and creating the owner's shielded resource.
pub struct Wrap {
    pub label: LabelInfo,
    pub owner: Owner,
    pub consumed: Resource,
    pub created: Resource,
}

/// The resources of a wrap of `amount` under `label` for `owner`.
/// `ephemeral_nonce` is the consumed resource's nonce, which its nullifier
/// and therefore the created resource's nonce derive from; `rand_seed` is
/// the created resource's.
pub fn wrap(
    label: LabelInfo,
    amount: u64,
    ephemeral_nonce: [u8; 32],
    owner: Owner,
    rand_seed: [u8; 32],
) -> Result<Wrap, ArmError> {
    let label_ref = calculate_label_ref(&label.forwarder_program_id, &label.spl_token_mint);
    let consumed = ephemeral_resource(
        label_ref,
        Digest::default(),
        amount as u128,
        ephemeral_nonce,
    );
    let created = Resource {
        logic_ref: TOKEN_TRANSFER_ID,
        label_ref,
        value_ref: owner.value_ref(),
        quantity: amount as u128,
        is_ephemeral: false,
        nonce: Resource::derive_nonce_from_nullifiers(
            0,
            &[consumed.nullifier(&NullifierKey::default())?],
        )?,
        nk_commitment: owner.nf_key.commit(),
        rand_seed,
    };
    Ok(Wrap {
        label,
        owner,
        consumed,
        created,
    })
}

impl Wrap {
    pub fn action_tree_root(&self) -> Result<Digest, ArmError> {
        action_tree_root(
            self.consumed.nullifier(&NullifierKey::default())?,
            &self.created,
        )
    }

    /// The text the user signs and the ed25519 instruction carries: base64
    /// of the sha256 of the 120-byte wrap message the forwarder recomputes
    /// from the proof-bound input.
    pub fn signed_message(&self, auth: &WrapAuth) -> Result<String, ArmError> {
        Ok(WrapMessage {
            forwarder_id: self.label.forwarder_program_id,
            token_mint: self.label.spl_token_mint,
            amount: self.consumed.quantity as u64,
            nonce: auth.info.nonce,
            deadline: auth.info.deadline,
            action_tree_root: self.action_tree_root()?.into(),
        }
        .base64_digest())
    }

    /// The action's witnesses. `discovery_pk` is the key the created
    /// resource's discovery payload is encrypted to.
    pub fn action(
        &self,
        auth: WrapAuth,
        discovery_pk: &AffinePoint,
        compliance: ComplianceParams,
    ) -> Result<TransferAction, ArmError> {
        let root = self.action_tree_root()?;
        Ok(TransferAction {
            compliance_witness: ComplianceWitness::from_parts(
                vec![ConsumedResourceWitness::from_resource(
                    self.consumed,
                    NullifierKey::default(),
                )],
                vec![self.created],
                INITIAL_ROOT,
                &compliance.rcv,
                compliance.kind_table,
            ),
            consumed_logic: TransferLogic::mint_resource_logic_with_wrap_auth(
                self.consumed,
                root,
                NullifierKey::default(),
                self.label.clone(),
                auth.user,
                auth.info,
            ),
            created_logic: TransferLogic::create_persistent_resource_logic(
                self.created,
                root,
                discovery_pk,
                self.owner.value.clone(),
                self.label.clone(),
            ),
        })
    }
}

/// An unwrap: the owner spends a shielded resource into an ephemeral one
/// whose logic commits the forwarder call releasing the escrowed tokens to
/// `recipient`.
pub struct Unwrap {
    pub label: LabelInfo,
    pub owner: Owner,
    pub recipient: [u8; 32],
    pub consumed: Resource,
    pub created: Resource,
}

/// The resources of an unwrap of `wrapped`, `owner`'s shielded resource
/// under `label`, to the Solana account `recipient`.
pub fn unwrap(
    label: LabelInfo,
    wrapped: Resource,
    owner: Owner,
    recipient: [u8; 32],
) -> Result<Unwrap, ArmError> {
    let created = ephemeral_resource(
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
    })
}

impl Unwrap {
    /// What the owner signs under `AUTH_SIGNATURE_DOMAIN`.
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
        compliance: ComplianceParams,
    ) -> Result<TransferAction, ArmError> {
        let root = self.action_tree_root()?;
        Ok(TransferAction {
            compliance_witness: ComplianceWitness::from_parts(
                vec![ConsumedResourceWitness::from_resource_with_path(
                    self.consumed,
                    self.owner.nf_key.clone(),
                    cm_merkle_path,
                )],
                vec![self.created],
                INITIAL_ROOT,
                &compliance.rcv,
                compliance.kind_table,
            ),
            consumed_logic: TransferLogic::consume_persistent_resource_logic(
                self.consumed,
                root,
                self.owner.nf_key.clone(),
                self.owner.value.clone(),
                auth_sig,
            ),
            created_logic: TransferLogic::burn_resource_logic(
                self.created,
                root,
                self.label.clone(),
                self.recipient,
            ),
        })
    }
}
