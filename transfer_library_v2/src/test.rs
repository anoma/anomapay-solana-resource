// Circuit tests for the v2 Solana token-transfer resource logic (with migration).
//
// These exercise the committed guest ELF (embedded as `TOKEN_TRANSFER_V2_ELF`)
// through `TransferLogicV2::prove`. Proving is slow without `RISC0_DEV_MODE=1`;
// set it when running these locally.
use anoma_rm_risc0::{
    Digest, NullifierKeyExt, logic_proof::LogicProver, nullifier_key::NullifierKey,
    resource::Resource,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::{SecretKey, generate_public_key},
};
use k256::Scalar;
use transfer_witness::{
    ValueInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_solana_account,
};

use crate::TransferLogicV2;

const FORWARDER_PROGRAM_ID_V1: [u8; 32] = [0u8; 32];
const FORWARDER_PROGRAM_ID_V2: [u8; 32] = [10u8; 32];
const UNEXPECTED_FORWARDER_PROGRAM_ID: [u8; 32] = [20u8; 32];
const SPL_TOKEN_MINT: [u8; 32] = [1u8; 32];
const SOLANA_ACCOUNT: [u8; 32] = [2u8; 32];
const QUANTITY: u128 = 1000;
const UNEXPECTED_QUANTITY: u128 = 1001;
const NF_KEY_BYTES: [u8; 32] = [3u8; 32];
const UNEXPECTED_NF_KEY_BYTES: [u8; 32] = [33u8; 32];
const WRAP_NONCE: u64 = 4;
const WRAP_DEADLINE: i64 = 1_800_000_000;
const ED25519_SIG: [u8; 64] = [6u8; 64];
const ED25519_IX_INDEX: u8 = 0;
const AUTH_SK: [u8; 32] = [7u8; 32];
const UNEXPECTED_AUTH_SK: [u8; 32] = [77u8; 32];
const ENCRYPTION_SK: u32 = 8u32;
const UNEXPECTED_ENCRYPTION_SK: u32 = 88u32;

// Create a sample persistent resource in v2 for testing.
fn create_persistent_resource_v2() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID_V2, &SPL_TOKEN_MINT);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());
    let value_info = ValueInfo {
        auth_pk,
        encryption_pk,
    };

    let value_ref = calculate_persistent_value_ref(&value_info);

    Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: false,
        nk_commitment,
        ..Default::default()
    }
}

// Create a sample ephemeral resource in v2 for testing. The unwrap path
// constrains the value_ref to the recipient Solana account; the migrate path
// uses it only as a consumed trigger.
fn create_ephemeral_resource_v2() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID_V2, &SPL_TOKEN_MINT);
    let value_ref = calculate_value_ref_from_solana_account(&SOLANA_ACCOUNT);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();

    Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        nk_commitment,
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: true,
        ..Default::default()
    }
}

// Create a sample persistent resource in v1 for testing.
fn create_persistent_resource_v1() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID_V1, &SPL_TOKEN_MINT);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());
    let value_info = ValueInfo {
        auth_pk,
        encryption_pk,
    };

    let value_ref = calculate_persistent_value_ref(&value_info);

    Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: false,
        nk_commitment,
        ..Default::default()
    }
}

// Create a valid migrate resource logic in v2 for testing.
fn create_migrate_resource_logic() -> TransferLogicV2 {
    use anoma_rm_risc0::merkle_path::MerklePath;
    use transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2;

    // Mock a resource to be migrated in v1.
    let resource_v1 = create_persistent_resource_v1();

    // Create the ephemeral resource in v2 to migrate resource_v1.
    let self_resource = create_ephemeral_resource_v2();

    // It should be the real root in practice.
    let action_tree_root = Digest::default();

    let nf_key = NullifierKey::from_bytes(NF_KEY_BYTES);

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);

    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN_V2, action_tree_root.as_bytes());

    TransferLogicV2::migrate_resource_logic(
        self_resource,
        action_tree_root,
        nf_key.clone(),
        FORWARDER_PROGRAM_ID_V2,
        SPL_TOKEN_MINT,
        resource_v1,
        nf_key,                // using the same nf_key for simplicity
        MerklePath::default(), // default path; only a real tx/action needs a valid path
        auth_pk,
        encryption_pk,
        auth_sig,
        FORWARDER_PROGRAM_ID_V1,
    )
}

#[test]
fn test_mint_v2() {
    use anoma_rm_risc0::proving_system::ProofType;

    let resource = create_ephemeral_resource_v2();
    let mut resource_logic = TransferLogicV2::mint_resource_logic_with_wrap_auth(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_PROGRAM_ID_V2,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
        WRAP_NONCE,
        WRAP_DEADLINE,
        ED25519_SIG,
        ED25519_IX_INDEX,
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    // A wrap must be triggered by a consumed resource.
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_burn_v2() {
    use anoma_rm_risc0::proving_system::ProofType;

    let resource = create_ephemeral_resource_v2();
    let mut resource_logic = TransferLogicV2::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_PROGRAM_ID_V2,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    // An unwrap must be triggered by a created resource.
    resource_logic.witness.is_consumed = true;
    resource_logic.witness.nf_key = Some(NullifierKey::from_bytes(NF_KEY_BYTES));
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_transfer_v2() {
    use anoma_rm_risc0::proving_system::ProofType;
    use anoma_rm_risc0_gadgets::encryption::{Ciphertext, random_keypair};
    use transfer_witness::ResourceWithLabel;
    use transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2;

    let consumed_resource = create_persistent_resource_v2();

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN_V2, action_tree_root.as_bytes());

    let consumed_resource_logic = TransferLogicV2::consume_persistent_resource_logic(
        consumed_resource,
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        auth_pk,
        encryption_pk,
        auth_sig,
    );

    let proof = consumed_resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    let created_resource = create_persistent_resource_v2();
    let (created_discovery_sk, created_discovery_pk) = random_keypair();
    let created_resource_logic = TransferLogicV2::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        auth_pk,
        encryption_pk,
        FORWARDER_PROGRAM_ID_V2,
        SPL_TOKEN_MINT,
    );

    let proof = created_resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    // check discovery ciphertext
    let discovery_ciphertext =
        Ciphertext::from_words(&proof.get_instance().unwrap().app_data.discovery_payload[0].blob);
    discovery_ciphertext.decrypt(&created_discovery_sk).unwrap();

    // check encryption
    let encryption_ciphertext =
        Ciphertext::from_words(&proof.get_instance().unwrap().app_data.resource_payload[0].blob);
    let plaintext = encryption_ciphertext.decrypt(&encryption_sk).unwrap();
    let expected_plaintext = bincode::serialize(&ResourceWithLabel {
        resource: created_resource,
        forwarder_program_id: FORWARDER_PROGRAM_ID_V2,
        spl_token_mint: SPL_TOKEN_MINT,
    })
    .unwrap();
    assert_eq!(plaintext.as_bytes(), expected_plaintext);

    // Deserialize to verify correctness
    let deserialized: ResourceWithLabel = bincode::deserialize(plaintext.as_bytes()).unwrap();
    assert_eq!(
        deserialized.forwarder_program_id, FORWARDER_PROGRAM_ID_V2,
        "Forwarder program id mismatch"
    );
    assert_eq!(
        deserialized.spl_token_mint, SPL_TOKEN_MINT,
        "SPL token mint mismatch"
    );
    assert_eq!(deserialized.resource, created_resource, "Resource mismatch");
}

#[test]
fn test_positive_migration() {
    use anoma_rm_risc0::proving_system::ProofType;

    let resource_logic = create_migrate_resource_logic();
    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();
}

#[test]
fn test_negative_migration_with_wrong_is_consumed_in_self_resource() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Migration must be triggered by a consumed resource.
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_missing_migrate_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info = None;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_is_ephemeral_in_migrate_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.resource.is_ephemeral = true; // should be false for a persistent resource
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_auth_pk_in_value_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
        let wrong_auth_pk = AuthorityVerifyingKey::from_signing_key(&wrong_auth_sk);
        migrate_info.value_info.auth_pk = wrong_auth_pk;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_encryption_pk_in_value_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_encryption_sk = SecretKey::new(Scalar::from(UNEXPECTED_ENCRYPTION_SK));
        let wrong_encryption_pk = generate_public_key(wrong_encryption_sk.inner());
        migrate_info.value_info.encryption_pk = wrong_encryption_pk;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_auth_sig() {
    use anoma_rm_risc0::proving_system::ProofType;

    // Wrong auth_sk.
    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
        let wrong_auth_sig = wrong_auth_sk.sign(
            transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2,
            resource_logic.witness.action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();

    // Wrong action_tree_root.
    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_action_tree_root = Digest::from_bytes([10u8; 32]);
        let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
        let wrong_auth_sig = auth_sk.sign(
            transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2,
            wrong_action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();

    // Wrong domain.
    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
        let wrong_auth_sig = auth_sk.sign(
            b"WrongDomain",
            resource_logic.witness.action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_quantity() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.resource.quantity = UNEXPECTED_QUANTITY;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_nf_key() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.nf_key = NullifierKey::from_bytes(UNEXPECTED_NF_KEY_BYTES);
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_forwarder_id_in_migrate_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.forwarder_program_id = UNEXPECTED_FORWARDER_PROGRAM_ID;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}
