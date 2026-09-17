// Circuit tests for the Solana token-transfer resource logic.
//
// These exercise the committed guest ELF (embedded as `TOKEN_TRANSFER_ELF`)
// through `TransferLogic::prove`. Proving is slow without `RISC0_DEV_MODE=1`;
// set it when running these locally.
use anoma_pa_solana_client::external_call::{OP_UNWRAP, OP_WRAP, SolanaExternalCall};
use anoma_rm_risc0::{
    Digest,
    logic_instance::LogicInstance,
    logic_proof::{LogicProver, LogicVerifier, get_instance, verify},
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::Resource,
    utils::words_to_bytes,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::{SecretKey, generate_public_key},
};
use k256::Scalar;
use transfer_witness::{
    AUTH_SIGNATURE_DOMAIN, FORWARDER_RESULT_SUCCESS, ValueInfo, calculate_label_ref,
    calculate_persistent_value_ref, calculate_value_ref_from_solana_account,
    call_type::{UNWRAP_SEGMENT_NUM_ACCOUNTS, WRAP_SEGMENT_NUM_ACCOUNTS},
};

use crate::TransferLogic;

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

// A persistent resource under the given forwarder program id.
fn create_persistent_resource(forwarder_program_id: [u8; 32]) -> Resource {
    let label_ref = calculate_label_ref(&forwarder_program_id, &SPL_TOKEN_MINT);
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

// An ephemeral resource under the forwarder. The unwrap path constrains the
// value_ref to the recipient Solana account; the wrap path ignores it.
fn create_ephemeral_resource() -> Resource {
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

#[test]
fn test_mint() {
    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::mint_resource_logic_with_wrap_auth(
        resource,
        Digest::default(), // dummy action_tree_root
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

    // A wrap must be triggered by a consumed resource.
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_burn() {
    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    verify(&proof).unwrap();

    // An unwrap must be triggered by a created resource.
    resource_logic.witness.is_consumed = true;
    resource_logic.witness.nf_key = Some(NullifierKey::from_bytes(NF_KEY_BYTES));
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_transfer() {
    use anoma_rm_risc0_gadgets::encryption::{Ciphertext, random_keypair};
    use transfer_witness::ResourceWithLabel;

    let consumed_resource = create_persistent_resource(FORWARDER_PROGRAM_ID);

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
    verify(&proof).unwrap();

    let created_resource = create_persistent_resource(FORWARDER_PROGRAM_ID);
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

    // check discovery ciphertext
    let discovery_ciphertext =
        Ciphertext::from_words(&get_instance(&proof).unwrap().app_data.discovery_payload[0].blob);
    discovery_ciphertext.decrypt(&created_discovery_sk).unwrap();

    // check encryption
    let encryption_ciphertext =
        Ciphertext::from_words(&get_instance(&proof).unwrap().app_data.resource_payload[0].blob);
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

/// The one external call a proven ephemeral witness commits to.
fn external_call(proof: &LogicVerifier) -> SolanaExternalCall {
    let instance: LogicInstance = get_instance(proof).unwrap();
    assert_eq!(instance.app_data.external_payload.len(), 1);
    SolanaExternalCall::decode(words_to_bytes(&instance.app_data.external_payload[0].blob))
        .expect("external-call blob should decode")
}

#[test]
fn wrap_external_call_commits_the_forwarder_segment() {
    let action_tree_root = Digest::from_bytes([9u8; 32]);
    let resource_logic = TransferLogic::mint_resource_logic_with_wrap_auth(
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

    let call = external_call(&proof);
    assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
    assert_eq!(call.num_accounts, WRAP_SEGMENT_NUM_ACCOUNTS);
    assert_eq!(call.expected_output, vec![FORWARDER_RESULT_SUCCESS]);
    // op(1) + token_mint(32) + amount(8) + user(32) + nonce(8) + deadline(8)
    // + action_tree_root(32) + ed25519_ix_index(1)
    assert_eq!(call.instruction_data.len(), 122);
    assert_eq!(call.instruction_data[0], OP_WRAP);
    assert_eq!(&call.instruction_data[1..33], &SPL_TOKEN_MINT, "token_mint");
    assert_eq!(
        u64::from_le_bytes(call.instruction_data[33..41].try_into().unwrap()),
        QUANTITY as u64,
        "amount"
    );
    assert_eq!(&call.instruction_data[41..73], &SOLANA_ACCOUNT, "user");
    assert_eq!(
        u64::from_le_bytes(call.instruction_data[73..81].try_into().unwrap()),
        WRAP_NONCE,
        "nonce"
    );
    assert_eq!(
        i64::from_le_bytes(call.instruction_data[81..89].try_into().unwrap()),
        WRAP_DEADLINE,
        "deadline"
    );
    assert_eq!(
        &call.instruction_data[89..121],
        action_tree_root.as_bytes(),
        "action_tree_root"
    );
    assert_eq!(
        call.instruction_data[121], ED25519_IX_INDEX,
        "ed25519_ix_index"
    );
}

#[test]
fn unwrap_external_call_commits_the_forwarder_segment() {
    let resource_logic = TransferLogic::burn_resource_logic(
        create_ephemeral_resource(),
        Digest::default(),
        FORWARDER_PROGRAM_ID,
        SPL_TOKEN_MINT,
        SOLANA_ACCOUNT,
    );
    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    let call = external_call(&proof);
    assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
    assert_eq!(call.num_accounts, UNWRAP_SEGMENT_NUM_ACCOUNTS);
    assert_eq!(call.expected_output, vec![FORWARDER_RESULT_SUCCESS]);
    // op(1) + token_mint(32) + amount(8) + recipient(32)
    assert_eq!(call.instruction_data.len(), 73);
    assert_eq!(call.instruction_data[0], OP_UNWRAP);
    assert_eq!(&call.instruction_data[1..33], &SPL_TOKEN_MINT, "token_mint");
    assert_eq!(
        u64::from_le_bytes(call.instruction_data[33..41].try_into().unwrap()),
        QUANTITY as u64,
        "amount"
    );
    assert_eq!(&call.instruction_data[41..73], &SOLANA_ACCOUNT, "recipient");
}
