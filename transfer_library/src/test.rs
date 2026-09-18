// Circuit tests for the Solana token-transfer resource logic.
//
// These exercise the committed guest ELF (embedded as `TOKEN_TRANSFER_ELF`)
// through `TransferLogic::prove`. Proving is slow without `RISC0_DEV_MODE=1`;
// set it when running these locally.
use anoma_rm_risc0::{
    Digest,
    compliance::hash_kind_table_entries,
    logic_proof::{LogicProver, get_instance, verify},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::Resource,
    transaction::Transaction,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::{Ciphertext, SecretKey, generate_public_key, random_keypair},
};
use k256::{AffinePoint, Scalar};
use transfer_witness::{
    AUTH_SIGNATURE_DOMAIN, LabelInfo, ResourceWithLabel, ValueInfo, calculate_label_ref,
    calculate_persistent_value_ref, calculate_value_ref_from_solana_account,
};

use crate::action::{ComplianceParams, Owner, WrapAuth, unwrap, wrap};
use crate::{TOKEN_TRANSFER_ELF, TOKEN_TRANSFER_ID, TransferLogic};

const FORWARDER_PROGRAM_ID: [u8; 32] = [10u8; 32];
const SPL_TOKEN_MINT: [u8; 32] = [1u8; 32];
const SOLANA_ACCOUNT: [u8; 32] = [2u8; 32];
const QUANTITY: u128 = 1000;
const NF_KEY_BYTES: [u8; 32] = [3u8; 32];
const WRAP_NONCE: u64 = 4;
const WRAP_DEADLINE: i64 = 1_800_000_000;
const ED25519_IX_INDEX: u8 = 0;
const AUTH_SK: [u8; 32] = [7u8; 32];
const ENCRYPTION_SK: u32 = 8u32;
const ACTION_TREE_ROOT: [u8; 32] = [9u8; 32];

/// The owner's authorization and encryption key pairs.
fn owner_keys() -> (
    AuthoritySigningKey,
    AuthorityVerifyingKey,
    SecretKey,
    AffinePoint,
) {
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());
    (auth_sk, auth_pk, encryption_sk, encryption_pk)
}

// A persistent resource owned by the test owner.
fn create_persistent_resource() -> Resource {
    let (_, auth_pk, _, encryption_pk) = owner_keys();
    let value_ref = calculate_persistent_value_ref(&ValueInfo {
        auth_pk,
        encryption_pk,
    });

    Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref: calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT),
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: false,
        nk_commitment: NullifierKey::from_bytes(NF_KEY_BYTES).commit(),
        ..Default::default()
    }
}

// An ephemeral resource under the forwarder. The unwrap path constrains the
// value_ref to the recipient Solana account; the wrap path ignores it.
fn create_ephemeral_resource() -> Resource {
    Resource {
        logic_ref: TransferLogic::verifying_key(),
        nk_commitment: NullifierKey::from_bytes(NF_KEY_BYTES).commit(),
        label_ref: calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT),
        value_ref: calculate_value_ref_from_solana_account(&SOLANA_ACCOUNT),
        quantity: QUANTITY,
        is_ephemeral: true,
        ..Default::default()
    }
}

#[test]
fn image_id_matches_the_embedded_guest() {
    assert_eq!(
        risc0_zkvm::compute_image_id(TOKEN_TRANSFER_ELF).unwrap(),
        *TOKEN_TRANSFER_ID
    );
}

#[test]
fn test_mint() {
    let action_tree_root = Digest::from_bytes(ACTION_TREE_ROOT);
    let mut resource_logic = TransferLogic::mint_resource_logic_with_wrap_auth(
        create_ephemeral_resource(),
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
        WRAP_NONCE,
        WRAP_DEADLINE,
        ED25519_IX_INDEX,
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    verify(&proof).unwrap();

    // The guest commits the external call the host-side witness computes.
    assert_eq!(
        get_instance(&proof).unwrap().app_data.external_payload,
        resource_logic
            .witness
            .ephemeral_resource_check(&ACTION_TREE_ROOT)
            .unwrap()
    );

    // A wrap must be triggered by a consumed resource.
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_burn() {
    let action_tree_root = Digest::from_bytes(ACTION_TREE_ROOT);
    let mut resource_logic = TransferLogic::burn_resource_logic(
        create_ephemeral_resource(),
        action_tree_root,
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    verify(&proof).unwrap();

    assert_eq!(
        get_instance(&proof).unwrap().app_data.external_payload,
        resource_logic
            .witness
            .ephemeral_resource_check(&ACTION_TREE_ROOT)
            .unwrap()
    );

    // An unwrap must be triggered by a created resource.
    resource_logic.witness.is_consumed = true;
    resource_logic.witness.nf_key = Some(NullifierKey::from_bytes(NF_KEY_BYTES));
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_transfer() {
    let (auth_sk, auth_pk, encryption_sk, encryption_pk) = owner_keys();
    let action_tree_root = Digest::from_bytes(ACTION_TREE_ROOT);
    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN, action_tree_root.as_bytes());

    let consumed_resource_logic = TransferLogic::consume_persistent_resource_logic(
        create_persistent_resource(),
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        auth_pk,
        encryption_pk,
        auth_sig,
    );
    let proof = consumed_resource_logic.prove(ProofType::Succinct).unwrap();
    verify(&proof).unwrap();

    let created_resource = create_persistent_resource();
    let (created_discovery_sk, created_discovery_pk) = random_keypair();
    let created_resource_logic = TransferLogic::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        auth_pk,
        encryption_pk,
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
    );
    let proof = created_resource_logic.prove(ProofType::Succinct).unwrap();
    verify(&proof).unwrap();
    let app_data = get_instance(&proof).unwrap().app_data;

    // The discovery ciphertext opens with the discovery key.
    Ciphertext::from_words(&app_data.discovery_payload[0].blob)
        .decrypt(&created_discovery_sk)
        .unwrap();

    // The resource payload opens with the owner's encryption key to the
    // resource and its label plaintext.
    let plaintext = Ciphertext::from_words(&app_data.resource_payload[0].blob)
        .decrypt(&encryption_sk)
        .unwrap();
    let expected = ResourceWithLabel {
        resource: created_resource,
        forwarder_program_id: FORWARDER_PROGRAM_ID,
        spl_token_mint: SPL_TOKEN_MINT,
    };
    assert_eq!(plaintext.as_bytes(), bincode::serialize(&expected).unwrap());
    let deserialized: ResourceWithLabel = bincode::deserialize(plaintext.as_bytes()).unwrap();
    assert_eq!(deserialized.resource, created_resource);
    assert_eq!(deserialized.forwarder_program_id, FORWARDER_PROGRAM_ID);
    assert_eq!(deserialized.spl_token_mint, SPL_TOKEN_MINT);
}

/// The deployment facts of the action tests: a fixed commitment randomness
/// and the empty kind table the adapter pins today.
fn compliance_params() -> ComplianceParams {
    ComplianceParams {
        rcv: Scalar::ONE.to_bytes().to_vec(),
        kind_table: vec![],
    }
}

fn tags_of(tx: &Transaction) -> Vec<Digest> {
    tx.actions.as_ref().unwrap()[0]
        .logic_verifier_inputs
        .iter()
        .map(|input| input.tag)
        .collect()
}

/// A wrap creates the owner's resource; the unwrap of that resource releases
/// its quantity to the recipient. Both actions prove against the embedded
/// guest and balance.
#[test]
fn wrap_then_unwrap_actions_prove_and_balance() {
    let (auth_sk, auth_pk, _, encryption_pk) = owner_keys();
    let owner = Owner {
        auth_pk,
        encryption_pk,
        nf_key: NullifierKey::from_bytes(NF_KEY_BYTES),
    };
    let label = LabelInfo {
        forwarder_program_id: FORWARDER_PROGRAM_ID,
        spl_token_mint: SPL_TOKEN_MINT,
    };
    let kind_table_commitment = hash_kind_table_entries(&[]);

    let wrap = wrap(label.clone(), QUANTITY as u64, [5u8; 32], &owner, [6u8; 32]).unwrap();
    assert_eq!(wrap.created.value_ref, owner.value_ref());
    assert_eq!(wrap.created.quantity, QUANTITY);
    let auth = WrapAuth {
        user: SOLANA_ACCOUNT,
        nonce: WRAP_NONCE,
        deadline: WRAP_DEADLINE,
        ed25519_ix_index: ED25519_IX_INDEX,
    };
    // base64 of a 32-byte hash: what the wallet signs.
    assert_eq!(wrap.signed_message(&auth).len(), 44);
    let (_, discovery_pk) = random_keypair();
    let wrap_tx = wrap
        .action(&auth, &owner, &discovery_pk, compliance_params())
        .prove(ProofType::Succinct)
        .unwrap();
    anoma_rm_risc0::transaction::verify(&wrap_tx, kind_table_commitment).unwrap();
    assert_eq!(
        tags_of(&wrap_tx),
        vec![wrap.consumed_nf, wrap.created.commitment()]
    );

    let unwrap = unwrap(label, wrap.created, &owner.nf_key, SOLANA_ACCOUNT).unwrap();
    assert_eq!(unwrap.created.quantity, QUANTITY);
    assert_eq!(
        unwrap.created.value_ref,
        calculate_value_ref_from_solana_account(&SOLANA_ACCOUNT)
    );
    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN, unwrap.action_tree_root.as_bytes());
    let unwrap_tx = unwrap
        .action(&owner, auth_sig, MerklePath::empty(), compliance_params())
        .prove(ProofType::Succinct)
        .unwrap();
    anoma_rm_risc0::transaction::verify(&unwrap_tx, kind_table_commitment).unwrap();
    assert_eq!(
        tags_of(&unwrap_tx),
        vec![
            wrap.created.nullifier(&owner.nf_key).unwrap(),
            unwrap.created.commitment()
        ]
    );
}
