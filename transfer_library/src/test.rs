// Circuit tests for the Solana token-transfer resource logic.
//
// These exercise the committed guest ELF (embedded in this crate as
// `TOKEN_TRANSFER_ELF`) through `TransferLogic::prove`. Proving is slow without
// `RISC0_DEV_MODE=1`; set it when running these locally.
use anoma_rm_risc0::{
    Digest, NullifierKeyExt, error::ArmError, logic_proof::LogicProver,
    nullifier_key::NullifierKey, proving_system::ProofType, resource::Resource,
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

use crate::TransferLogic;

// Guest panics surface as ArmError::ProveFailed wrapping the inner panic message,
// which in turn embeds the Debug of the ArmError produced by the witness constraint.
// We assert the wrapper variant and look for a substring identifying the root cause.
fn assert_prove_failed_with(resource_logic: &TransferLogic, expected_substr: &str) {
    let err = resource_logic
        .prove(ProofType::Succinct)
        .expect_err("prove was expected to fail");
    match &err {
        ArmError::ProveFailed(msg) => assert!(
            msg.contains(expected_substr),
            "expected ProveFailed message to contain {expected_substr:?}, got: {msg}"
        ),
        other => {
            panic!("expected ArmError::ProveFailed containing {expected_substr:?}, got: {other:?}")
        }
    }
}

const FORWARDER_PROGRAM_ID: [u8; 32] = [0u8; 32];
const SPL_TOKEN_MINT: [u8; 32] = [1u8; 32];
const UNEXPECTED_SPL_TOKEN_MINT: [u8; 32] = [11u8; 32];
const SOLANA_ACCOUNT: [u8; 32] = [2u8; 32];
const UNEXPECTED_SOLANA_ACCOUNT: [u8; 32] = [22u8; 32];
const QUANTITY: u128 = 1000;
const NF_KEY_BYTES: [u8; 32] = [3u8; 32];
const WRAP_NONCE: u64 = 4;
const WRAP_DEADLINE: i64 = 1_800_000_000;
const ED25519_SIG: [u8; 64] = [6u8; 64];
const ED25519_IX_INDEX: u8 = 0;
const AUTH_SK: [u8; 32] = [7u8; 32];
const UNEXPECTED_AUTH_SK: [u8; 32] = [77u8; 32];
const ENCRYPTION_SK: u32 = 8;
const UNEXPECTED_ENCRYPTION_SK: u32 = 88;

// Create a sample ephemeral resource for a wrap (mint). The wrap path does not
// constrain the value_ref, only the label_ref.
fn create_wrap_ephemeral_resource() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();

    Resource {
        logic_ref: TransferLogic::verifying_key(),
        nk_commitment,
        label_ref,
        quantity: QUANTITY,
        is_ephemeral: true,
        ..Default::default()
    }
}

// Create a sample ephemeral resource for an unwrap (burn). The unwrap path
// constrains the value_ref to the recipient Solana account.
fn create_unwrap_ephemeral_resource() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT);
    let value_ref = calculate_value_ref_from_solana_account(&SOLANA_ACCOUNT);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();

    Resource {
        logic_ref: TransferLogic::verifying_key(),
        nk_commitment,
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: true,
        ..Default::default()
    }
}

// Create a sample persistent resource for testing.
fn create_persistent_resource() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT);
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
        logic_ref: TransferLogic::verifying_key(),
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: false,
        nk_commitment,
        ..Default::default()
    }
}

fn wrap_resource_logic() -> TransferLogic {
    TransferLogic::mint_resource_logic_with_wrap_auth(
        create_wrap_ephemeral_resource(),
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
        WRAP_NONCE,
        WRAP_DEADLINE,
        ED25519_SIG,
        ED25519_IX_INDEX,
    )
}

#[test]
fn test_mint() {
    let resource_logic = wrap_resource_logic();

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    proof.verify().unwrap();
}

#[test]
fn test_burn() {
    let resource_logic = TransferLogic::burn_resource_logic(
        create_unwrap_ephemeral_resource(),
        Digest::default(), // dummy action_tree_root
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    proof.verify().unwrap();
}

#[test]
fn test_transfer() {
    use anoma_rm_risc0_gadgets::encryption::{Ciphertext, random_keypair};
    use transfer_witness::{AUTH_SIGNATURE_DOMAIN, ResourceWithLabel};

    let consumed_resource = create_persistent_resource();

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN, action_tree_root.as_bytes());

    let consumed_resource_logic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource,
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        auth_pk,
        encryption_pk,
        auth_sig,
    );

    let proof = consumed_resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

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
        forwarder_program_id: FORWARDER_PROGRAM_ID,
        spl_token_mint: SPL_TOKEN_MINT,
    })
    .unwrap();
    assert_eq!(plaintext.as_bytes(), expected_plaintext);

    // Deserialize to verify correctness
    let deserialized: ResourceWithLabel = bincode::deserialize(plaintext.as_bytes()).unwrap();
    assert_eq!(
        deserialized.forwarder_program_id, FORWARDER_PROGRAM_ID,
        "Forwarder program id mismatch"
    );
    assert_eq!(
        deserialized.spl_token_mint, SPL_TOKEN_MINT,
        "SPL token mint mismatch"
    );
    assert_eq!(deserialized.resource, created_resource, "Resource mismatch");
}

#[test]
fn test_missing_nf_key() {
    let mut resource_logic = wrap_resource_logic();

    // Remove the nullifier key to simulate missing nf_key
    resource_logic.witness.nf_key = None;

    assert_prove_failed_with(&resource_logic, "Nullifier key");
}

#[test]
fn test_missing_forwarder_info() {
    let mut resource_logic = wrap_resource_logic();

    // Remove the wrap auth info to simulate missing wrap auth info
    let mut forwarder_info = resource_logic.witness.forwarder_info.unwrap();
    forwarder_info.wrap_auth_info = None;
    resource_logic.witness.forwarder_info = Some(forwarder_info);

    assert_prove_failed_with(&resource_logic, "Wrap auth info");

    // Remove the forwarder info to simulate missing forwarder info
    resource_logic.witness.forwarder_info = None;

    assert_prove_failed_with(&resource_logic, "Forwarder info");
}

#[test]
fn test_missing_label_info() {
    let mut resource_logic = wrap_resource_logic();

    // Remove the label info to simulate missing label info
    resource_logic.witness.label_info = None;

    assert_prove_failed_with(&resource_logic, "Label info");
}

#[test]
fn test_wrong_label_ref() {
    let mut resource_logic = wrap_resource_logic();

    // Tamper with the label_info so the derived label_ref no longer matches
    resource_logic
        .witness
        .label_info
        .as_mut()
        .unwrap()
        .spl_token_mint[0] ^= 0xFF;

    assert_prove_failed_with(&resource_logic, "Invalid resource label_ref");
}

#[test]
fn test_wrong_call_type_for_wrap() {
    let mut resource_logic = wrap_resource_logic();

    // Change call type to Unwrap to simulate wrong call type for wrap
    resource_logic
        .witness
        .forwarder_info
        .as_mut()
        .unwrap()
        .call_type = transfer_witness::call_type::CallType::Unwrap;

    // The wrap resource is consumed, so the Unwrap branch rejects it.
    assert_prove_failed_with(
        &resource_logic,
        "Token unwraps must be triggered by a created resource",
    );
}

#[test]
fn test_wrong_call_type_for_unwrap() {
    let mut resource_logic = TransferLogic::burn_resource_logic(
        create_unwrap_ephemeral_resource(),
        Digest::default(), // dummy action_tree_root
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
    );

    // Change call type to Wrap to simulate wrong call type for unwrap
    resource_logic
        .witness
        .forwarder_info
        .as_mut()
        .unwrap()
        .call_type = transfer_witness::call_type::CallType::Wrap;

    // The unwrap resource is created (not consumed), so the Wrap branch rejects it.
    assert_prove_failed_with(
        &resource_logic,
        "Token wraps must be triggered by a consumed resource",
    );
}

#[test]
fn test_invalid_value_ref_for_unwrap() {
    // Unexpected recipient account: resource value_ref commits to SOLANA_ACCOUNT
    // but the forwarder is told to pay out UNEXPECTED_SOLANA_ACCOUNT.
    let resource_logic = TransferLogic::burn_resource_logic(
        create_unwrap_ephemeral_resource(),
        Digest::default(), // dummy action_tree_root
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        UNEXPECTED_SOLANA_ACCOUNT, // Unexpected solana_account
    );

    assert_prove_failed_with(&resource_logic, "Invalid resource value_ref");

    // Unexpected token mint: resource label_ref no longer matches the label info.
    let mut resource = create_unwrap_ephemeral_resource();
    resource.label_ref = calculate_label_ref(&FORWARDER_PROGRAM_ID, &UNEXPECTED_SPL_TOKEN_MINT);
    let resource_logic = TransferLogic::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
    );

    assert_prove_failed_with(&resource_logic, "Invalid resource label_ref");
}

fn create_persistent_consumed_resource_logic() -> TransferLogic {
    use transfer_witness::AUTH_SIGNATURE_DOMAIN;

    let consumed_resource = create_persistent_resource();

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN, action_tree_root.as_bytes());

    let resource_logic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource,
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        auth_pk,
        encryption_pk,
        auth_sig,
    );

    // Positive test
    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    resource_logic
}

#[test]
fn test_negative_persistent_resource_consumption_with_missing_info() {
    let resource_logic = create_persistent_consumed_resource_logic();

    // Remove the auth_sig to simulate missing auth_sig
    let mut resource_logic_with_missing_auth_sig = resource_logic.clone();
    resource_logic_with_missing_auth_sig.witness.auth_sig = None;
    assert_prove_failed_with(&resource_logic_with_missing_auth_sig, "Auth signature");

    // Remove the value_info to simulate missing value_info
    let mut resource_logic_with_missing_value_info = resource_logic.clone();
    resource_logic_with_missing_value_info.witness.value_info = None;
    assert_prove_failed_with(&resource_logic_with_missing_value_info, "Value info");
}

#[test]
fn test_negative_persistent_resource_consumption_with_invalid_value_info() {
    let resource_logic = create_persistent_consumed_resource_logic();

    // Wrong auth_pk in value_info
    let mut resource_logic_with_wrong_auth_pk = resource_logic.clone();
    let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
    let wrong_auth_pk = AuthorityVerifyingKey::from_signing_key(&wrong_auth_sk);
    resource_logic_with_wrong_auth_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .auth_pk = wrong_auth_pk;
    assert_prove_failed_with(&resource_logic_with_wrong_auth_pk, "InvalidResourceValueRef");

    // Wrong encryption_pk in value_info
    let mut resource_logic_with_wrong_encryption_pk = resource_logic.clone();
    let wrong_encryption_sk = SecretKey::new(Scalar::from(UNEXPECTED_ENCRYPTION_SK));
    let wrong_encryption_pk = generate_public_key(wrong_encryption_sk.inner());
    resource_logic_with_wrong_encryption_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .encryption_pk = wrong_encryption_pk;
    assert_prove_failed_with(
        &resource_logic_with_wrong_encryption_pk,
        "InvalidResourceValueRef",
    );
}

#[test]
fn test_negative_persistent_resource_consumption_with_invalid_auth_sig() {
    let resource_logic = create_persistent_consumed_resource_logic();
    let action_tree_root = Digest::default(); // dummy action_tree_root

    // Wrong auth_sig
    let mut resource_logic_with_wrong_auth_sig = resource_logic.clone();
    let auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
    let wrong_auth_sig = auth_sk.sign(
        transfer_witness::AUTH_SIGNATURE_DOMAIN,
        action_tree_root.as_bytes(),
    );
    resource_logic_with_wrong_auth_sig.witness.auth_sig = Some(wrong_auth_sig);
    assert_prove_failed_with(&resource_logic_with_wrong_auth_sig, "InvalidSignature");

    // Wrong action_tree_root
    let mut resource_logic_with_wrong_action_tree_root = resource_logic.clone();
    let wrong_action_tree_root = Digest::from_bytes([1u8; 32]);
    resource_logic_with_wrong_action_tree_root
        .witness
        .action_tree_root = wrong_action_tree_root;
    assert_prove_failed_with(
        &resource_logic_with_wrong_action_tree_root,
        "InvalidSignature",
    );

    // Wrong AUTH_SIGNATURE_DOMAIN
    let mut resource_logic_with_wrong_auth_signature_domain = resource_logic.clone();
    let wrong_auth_signature_domain = b"wrong_domain";
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let wrong_auth_sig = auth_sk.sign(wrong_auth_signature_domain, action_tree_root.as_bytes());
    resource_logic_with_wrong_auth_signature_domain
        .witness
        .auth_sig = Some(wrong_auth_sig);
    assert_prove_failed_with(
        &resource_logic_with_wrong_auth_signature_domain,
        "InvalidSignature",
    );
}

fn create_persistent_created_resource_logic() -> TransferLogic {
    use anoma_rm_risc0_gadgets::encryption::random_keypair;

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let created_resource = create_persistent_resource();
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let resource_logic = TransferLogic::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        auth_pk,
        encryption_pk,
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
    );

    // Positive test
    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    resource_logic
}

#[test]
fn test_negative_persistent_resource_creation_with_missing_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Remove the label_info to simulate missing label_info
    let mut resource_logic_with_missing_label_info = resource_logic.clone();
    resource_logic_with_missing_label_info.witness.label_info = None;
    assert_prove_failed_with(&resource_logic_with_missing_label_info, "Label info");

    // Remove the value_info to simulate missing value_info
    let mut resource_logic_with_missing_value_info = resource_logic.clone();
    resource_logic_with_missing_value_info.witness.value_info = None;
    assert_prove_failed_with(&resource_logic_with_missing_value_info, "Value info");

    // Remove the encryption_info to simulate missing encryption_info
    let mut resource_logic_with_missing_encryption_info = resource_logic.clone();
    resource_logic_with_missing_encryption_info
        .witness
        .encryption_info = None;
    assert_prove_failed_with(&resource_logic_with_missing_encryption_info, "Encryption info");
}

#[test]
fn test_negative_persistent_resource_creation_with_invalid_label_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Wrong forwarder program id in label_info
    let mut resource_logic_with_wrong_forwarder = resource_logic.clone();
    resource_logic_with_wrong_forwarder
        .witness
        .label_info
        .as_mut()
        .unwrap()
        .forwarder_program_id[0] ^= 0xFF;
    assert_prove_failed_with(
        &resource_logic_with_wrong_forwarder,
        "Invalid resource label_ref",
    );

    // Wrong spl_token_mint in label_info
    let mut resource_logic_with_wrong_mint = resource_logic.clone();
    resource_logic_with_wrong_mint
        .witness
        .label_info
        .as_mut()
        .unwrap()
        .spl_token_mint[0] ^= 0xFF;
    assert_prove_failed_with(&resource_logic_with_wrong_mint, "Invalid resource label_ref");
}

#[test]
fn test_negative_persistent_resource_creation_with_invalid_value_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Wrong auth_pk in value_info
    let mut resource_logic_with_wrong_auth_pk = resource_logic.clone();
    let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
    let wrong_auth_pk = AuthorityVerifyingKey::from_signing_key(&wrong_auth_sk);
    resource_logic_with_wrong_auth_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .auth_pk = wrong_auth_pk;
    assert_prove_failed_with(&resource_logic_with_wrong_auth_pk, "InvalidResourceValueRef");

    // Wrong encryption_pk in value_info
    let mut resource_logic_with_wrong_encryption_pk = resource_logic.clone();
    let wrong_encryption_sk = SecretKey::new(Scalar::from(UNEXPECTED_ENCRYPTION_SK));
    let wrong_encryption_pk = generate_public_key(wrong_encryption_sk.inner());
    resource_logic_with_wrong_encryption_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .encryption_pk = wrong_encryption_pk;
    assert_prove_failed_with(
        &resource_logic_with_wrong_encryption_pk,
        "InvalidResourceValueRef",
    );
}

#[test]
fn test_negative_persistent_resource_creation_with_invalid_encryption_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Invalid encryption nonce in encryption_info
    let mut resource_logic_with_invalid_encryption_nonce = resource_logic.clone();
    resource_logic_with_invalid_encryption_nonce
        .witness
        .encryption_info
        .as_mut()
        .unwrap()
        .encryption_nonce = [0u8; 13].to_vec(); // should be 12 bytes

    assert_prove_failed_with(
        &resource_logic_with_invalid_encryption_nonce,
        "InvalidEncryptionNonce",
    );
}
