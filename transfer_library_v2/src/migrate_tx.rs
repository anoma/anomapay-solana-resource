use crate::TransferLogicV2;
use anoma_rm_risc0::{
    ActionExt, CoreDeltaWitness, Digest, TransactionExt,
    action::Action,
    action_tree::MerkleTree,
    compliance::ComplianceWitness,
    compliance_unit::create_compliance_unit,
    delta_proof::DeltaWitness,
    error::ArmError,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::Resource,
    transaction::{Delta, Transaction},
};
use anoma_rm_risc0_gadgets::authority::{AuthoritySignature, AuthorityVerifyingKey};
use k256::AffinePoint;

/// Keccak256 hash function used for the ARM delta proof message. This matches the
/// convention exercised across the ARM test suite and language bindings.
pub fn hash_msg_keccak(msg: &[u8]) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};
    Keccak256::digest(msg).into()
}

#[allow(clippy::too_many_arguments)]
pub fn construct_migrate_tx(
    // Parameters for the consumed (ephemeral v2) resource
    consumed_resource: Resource,
    latest_cm_tree_root: Digest,
    consumed_nf_key: NullifierKey,
    forwarder_program_id: [u8; 32],
    spl_token_mint: [u8; 32],

    // Parameters for the migrated resource (v1)
    migrated_resource: Resource,
    migrated_nf_key: NullifierKey,
    migrated_resource_path: MerklePath,
    migrated_auth_pk: AuthorityVerifyingKey,
    migrated_encryption_pk: AffinePoint,
    migrated_auth_sig: AuthoritySignature,
    migrated_forwarder_program_id: [u8; 32],

    // Parameters for the created (persistent v2) resource
    created_resource: Resource,
    created_discovery_pk: AffinePoint,
    created_auth_pk: AuthorityVerifyingKey,
    created_encryption_pk: AffinePoint,
) -> Result<Transaction, ArmError> {
    // Action tree
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key)?;
    let created_cm = created_resource.commitment();
    let action_tree_root = MerkleTree::new(vec![consumed_nf, created_cm]).root()?;

    // Generate compliance units
    let compliance_witness = ComplianceWitness::from_resources(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key.clone(),
        created_resource,
    );
    let compliance_unit = create_compliance_unit(&compliance_witness, ProofType::Groth16)?;

    // Generate logic proofs
    let consumed_resource_logic = TransferLogicV2::migrate_resource_logic(
        consumed_resource,
        action_tree_root,
        consumed_nf_key,
        forwarder_program_id,
        spl_token_mint,
        migrated_resource,
        migrated_nf_key,
        migrated_resource_path,
        migrated_auth_pk,
        migrated_encryption_pk,
        migrated_auth_sig,
        migrated_forwarder_program_id,
    );
    let consumed_logic_proof = consumed_resource_logic.prove(ProofType::Groth16)?;

    let created_resource_logic = TransferLogicV2::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        created_auth_pk,
        created_encryption_pk,
        forwarder_program_id,
        spl_token_mint,
    );
    let created_logic_proof = created_resource_logic.prove(ProofType::Groth16)?;

    // Construct the action
    let action = Action::new(
        vec![compliance_unit],
        vec![consumed_logic_proof, created_logic_proof],
    )?;

    // Construct the transaction
    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv)?;
    let tx = Transaction::create(
        vec![action],
        Delta::Witness(CoreDeltaWitness(delta_witness.to_bytes())),
    );
    let balanced_tx = tx.generate_delta_proof(hash_msg_keccak)?;
    Ok(balanced_tx)
}

#[test]
fn simple_migrate_test() {
    use anoma_rm_risc0::{NullifierKeyExt, initial_root};
    use anoma_rm_risc0_gadgets::{
        authority::{AuthoritySigningKey, AuthorityVerifyingKey},
        encryption::random_keypair,
    };
    use transfer_witness::{ValueInfo, calculate_label_ref, calculate_persistent_value_ref};
    use transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2;

    // Common parameters
    let forwarder_program_id_v1 = [0u8; 32];
    let logic_ref_v1 = Digest::default();
    let forwarder_program_id_v2 = [1u8; 32];
    let spl_token_mint = [2u8; 32];
    let quantity = 100;
    let label_ref = calculate_label_ref(&forwarder_program_id_v1, &spl_token_mint);
    let label_ref_v2 = calculate_label_ref(&forwarder_program_id_v2, &spl_token_mint);

    // Construct the migrated resource
    let migrated_auth_sk = AuthoritySigningKey::from_bytes(&[9u8; 32]).unwrap();
    let migrated_auth_pk = AuthorityVerifyingKey::from_signing_key(&migrated_auth_sk);
    let (_migrated_encryption_sk, migrated_encryption_pk) = random_keypair();
    let migrated_nf_key = NullifierKey::default();
    let migrated_nf_cm = migrated_nf_key.commit();
    let value_info = ValueInfo {
        auth_pk: migrated_auth_pk,
        encryption_pk: migrated_encryption_pk,
    };
    let migrated_value_ref = calculate_persistent_value_ref(&value_info);
    let migrated_resource = Resource {
        logic_ref: logic_ref_v1,
        nk_commitment: migrated_nf_cm,
        label_ref,
        value_ref: migrated_value_ref,
        quantity,
        is_ephemeral: false,
        ..Default::default()
    };

    // Construct the consumed resource
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let consumed_resource = Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        label_ref: label_ref_v2,
        nk_commitment: consumed_nf_cm,
        quantity,
        is_ephemeral: true,
        ..Default::default()
    };

    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    // Fetch the latest cm tree root from the chain
    let latest_cm_tree_root = initial_root();

    // Generate the created resource
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let created_auth_sk = AuthoritySigningKey::new();
    let created_auth_pk = AuthorityVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let value_info = ValueInfo {
        auth_pk: created_auth_pk,
        encryption_pk: created_encryption_pk,
    };
    let created_resource = Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        nk_commitment: created_nf_cm,
        label_ref: label_ref_v2,
        value_ref: calculate_persistent_value_ref(&value_info),
        quantity,
        is_ephemeral: false,
        nonce: consumed_nf.as_bytes().try_into().unwrap(),
        ..Default::default()
    };

    let created_cm = created_resource.commitment();

    // Generate the authorization signature
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let migrated_auth_sig = migrated_auth_sk.sign(
        AUTH_SIGNATURE_DOMAIN_V2,
        action_tree.root().unwrap().as_bytes(),
    );

    // Construct the migration transaction
    let tx = construct_migrate_tx(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key,
        forwarder_program_id_v2,
        spl_token_mint,
        migrated_resource,
        migrated_nf_key,
        MerklePath::from_path(&[]), // dummy path
        migrated_auth_pk,
        migrated_encryption_pk,
        migrated_auth_sig,
        forwarder_program_id_v1,
        created_resource,
        created_discovery_pk,
        created_auth_pk,
        created_encryption_pk,
    )
    .unwrap();

    // Verify the transaction
    tx.verify(hash_msg_keccak).unwrap();
}
