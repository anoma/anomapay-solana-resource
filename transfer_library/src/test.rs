// Circuit tests for the Solana token-transfer resource logic.
//
// These exercise the committed guest ELF (embedded as `TOKEN_TRANSFER_ELF`)
// through `TransferLogic::prove`. Proving is slow without `RISC0_DEV_MODE=1`;
// set it when running these locally.
use anoma_pa_solana_client::external_call::{OutputMode, SolanaExternalCall};
use anoma_rm_risc0::{
    Digest,
    action_tree::ActionTree,
    compliance,
    kind_tree::KindTree,
    logic_instance::LogicInstance,
    logic_proof::{LogicProver, LogicVerifier, get_instance, verify},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::{JournalEncoding, ProofType},
    resource::Resource,
    transaction::Transaction,
    utils::{hash_bytes, words_to_bytes},
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::{Ciphertext, SecretKey, generate_public_key, random_keypair},
};
use anomapay_spl_token_forwarder_client as forwarder_client;
use anomapay_spl_token_forwarder_client::generated::spl_token_forwarder::constants::{
    OP_UNWRAP, OP_WRAP,
};
use k256::{AffinePoint, Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, OsRng, SeedableRng};
use std::sync::LazyLock;
use transfer_witness::{
    AUTH_SIGNATURE_DOMAIN, LabelInfo, LogicCircuit, ResourceWithLabel, TokenTransferWitness,
    ValueInfo, WrapAuthInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_solana_account, wire,
};

use crate::action::{ComplianceParams, Owner, TransferAction, Wrap, WrapAuth, build, unwrap, wrap};
use crate::{TOKEN_TRANSFER_ELF, TOKEN_TRANSFER_ID, TransferLogic};
use hex_literal::hex;

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

fn label() -> LabelInfo {
    LabelInfo {
        forwarder_program_id: FORWARDER_PROGRAM_ID,
        spl_token_mint: SPL_TOKEN_MINT,
    }
}

fn wrap_auth() -> WrapAuthInfo {
    WrapAuthInfo {
        nonce: WRAP_NONCE,
        deadline: WRAP_DEADLINE,
        signature: [0x5a; 64],
        ed25519_ix_index: ED25519_IX_INDEX,
    }
}

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

fn owner_value() -> ValueInfo {
    let (_, auth_pk, _, encryption_pk) = owner_keys();
    ValueInfo {
        auth_pk,
        encryption_pk,
    }
}

// A persistent resource owned by the test owner.
fn create_persistent_resource() -> Resource {
    Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref: calculate_label_ref(&FORWARDER_PROGRAM_ID, &SPL_TOKEN_MINT),
        value_ref: calculate_persistent_value_ref(&owner_value()),
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

/// The guest commits the external call the host-side witness computes.
fn assert_commits_external_call(proof: &LogicVerifier, logic: &TransferLogic) {
    assert_eq!(
        get_instance(proof).unwrap().app_data.external_payload,
        logic
            .witness
            .ephemeral_resource_check(&ACTION_TREE_ROOT)
            .unwrap()
    );
}

#[test]
fn image_id_matches_the_embedded_guest() {
    assert_eq!(
        risc0_zkvm::compute_image_id(TOKEN_TRANSFER_ELF).unwrap(),
        TOKEN_TRANSFER_ID
    );
}

/// The guest declares the adapter's external call and the forwarder's wrap
/// and unwrap formats itself (`transfer_witness::wire`), so no client
/// release reaches its VK; each is the clients' byte for byte.
#[test]
fn the_guests_wire_formats_are_the_clients() {
    let token_mint = [0x21; 32];
    let user = [0x31; 32];
    let action_tree_root = [0x41; 32];
    let signature: [u8; 64] = core::array::from_fn(|i| i as u8);
    let guest_wrap = wire::encode_wrap_forwarder_input(&wire::WrapInput {
        token_mint,
        amount: 0x0102_0304_0506_0708,
        user,
        nonce: 0x1112_1314_1516_1718,
        deadline: -5,
        action_tree_root,
        signature,
        ed25519_ix_index: 3,
    });
    let client_wrap = forwarder_client::encode_wrap_forwarder_input(&forwarder_client::WrapInput {
        token_mint,
        amount: 0x0102_0304_0506_0708,
        user,
        nonce: 0x1112_1314_1516_1718,
        deadline: -5,
        action_tree_root,
        signature,
        ed25519_ix_index: 3,
    });
    println!("wrap input: guest {guest_wrap:02x?}, client {client_wrap:02x?}");
    assert_eq!(guest_wrap, client_wrap, "the wrap input");

    let guest_unwrap = wire::encode_unwrap_forwarder_input(&token_mint, 0x0a0b_0c0d, &user);
    let client_unwrap =
        forwarder_client::encode_unwrap_forwarder_input(&token_mint, 0x0a0b_0c0d, &user);
    println!("unwrap input: guest {guest_unwrap:02x?}, client {client_unwrap:02x?}");
    assert_eq!(guest_unwrap, client_unwrap, "the unwrap input");

    assert_eq!(wire::OP_WRAP, OP_WRAP, "OP_WRAP");
    assert_eq!(wire::OP_UNWRAP, OP_UNWRAP, "OP_UNWRAP");
    assert_eq!(
        wire::FORWARDER_SEGMENT_HEAD_NUM_ACCOUNTS,
        forwarder_client::FORWARDER_SEGMENT_HEAD_NUM_ACCOUNTS,
        "the segment head's account count"
    );
    assert_eq!(
        wire::FORWARDER_WRAP_NUM_ACCOUNTS,
        forwarder_client::FORWARDER_WRAP_NUM_ACCOUNTS,
        "the wrap segment's account count"
    );
    assert_eq!(
        wire::FORWARDER_UNWRAP_NUM_ACCOUNTS,
        forwarder_client::FORWARDER_UNWRAP_NUM_ACCOUNTS,
        "the unwrap segment's account count"
    );

    let guest_call = wire::SolanaExternalCall {
        program_id: FORWARDER_PROGRAM_ID,
        instruction_data: guest_wrap.clone(),
        expected_output: vec![7, 8, 9],
        output_mode: wire::OutputMode::ReturnData,
        num_accounts: 10,
    }
    .encode();
    let client_call = SolanaExternalCall {
        program_id: FORWARDER_PROGRAM_ID,
        instruction_data: guest_wrap,
        expected_output: vec![7, 8, 9],
        output_mode: OutputMode::ReturnData,
        num_accounts: 10,
    }
    .encode();
    println!("external call: guest {guest_call:02x?}, client {client_call:02x?}");
    assert_eq!(guest_call, client_call, "the external call");
}

/// A wrap's ephemeral resource of `quantity`.
fn wrap_witness(quantity: u128) -> TokenTransferWitness {
    TransferLogic::mint_resource_logic_with_wrap_auth(
        Resource {
            quantity,
            ..create_ephemeral_resource()
        },
        Digest::from_bytes(ACTION_TREE_ROOT),
        NullifierKey::from_bytes(NF_KEY_BYTES),
        label(),
        SOLANA_ACCOUNT,
        wrap_auth(),
    )
    .witness
}

/// An unwrap's ephemeral resource of `quantity` to `SOLANA_ACCOUNT`.
fn unwrap_witness(quantity: u128) -> TokenTransferWitness {
    TransferLogic::burn_resource_logic(
        Resource {
            quantity,
            ..create_ephemeral_resource()
        },
        Digest::from_bytes(ACTION_TREE_ROOT),
        label(),
        SOLANA_ACCOUNT,
    )
    .witness
}

/// The external call `witness` commits, decoded by the adapter's client.
fn witness_external_call(witness: TokenTransferWitness) -> SolanaExternalCall {
    let external_payload = witness
        .ephemeral_resource_check(&ACTION_TREE_ROOT)
        .expect("configured ephemeral witness should emit an external call");
    assert_eq!(external_payload.len(), 1);
    SolanaExternalCall::decode(words_to_bytes(&external_payload[0].blob))
        .expect("external-call blob should decode")
}

#[test]
fn wrap_external_call_rejects_quantity_above_u64() {
    let err = wrap_witness(u64::MAX as u128 + 1)
        .ephemeral_resource_check(&ACTION_TREE_ROOT)
        .expect_err("wrap witness must reject oversized SPL amount");
    assert!(
        err.to_string().contains("exceeds u64::MAX"),
        "unexpected error: {err}"
    );
}

#[test]
fn unwrap_external_call_rejects_quantity_above_u64() {
    let err = unwrap_witness(u64::MAX as u128 + 1)
        .ephemeral_resource_check(&ACTION_TREE_ROOT)
        .expect_err("unwrap witness must reject oversized SPL amount");
    assert!(
        err.to_string().contains("exceeds u64::MAX"),
        "unexpected error: {err}"
    );
}

/// The wrap call commits the forwarder's segment and exactly the forwarder
/// client's bytes for every witness value, the action tree root included.
#[test]
fn wrap_external_call_commits_the_forwarder_segment() {
    let call = witness_external_call(wrap_witness(u64::MAX as u128));
    let auth = wrap_auth();
    assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
    assert_eq!(
        call.num_accounts,
        forwarder_client::FORWARDER_WRAP_NUM_ACCOUNTS
    );
    assert!(call.expected_output.is_empty());
    assert_eq!(call.output_mode, OutputMode::ReturnData);
    assert_eq!(call.instruction_data[0], OP_WRAP);
    assert_eq!(
        call.instruction_data,
        forwarder_client::encode_wrap_forwarder_input(&forwarder_client::WrapInput {
            token_mint: SPL_TOKEN_MINT,
            amount: u64::MAX,
            user: SOLANA_ACCOUNT,
            nonce: auth.nonce,
            deadline: auth.deadline,
            action_tree_root: ACTION_TREE_ROOT,
            signature: auth.signature,
            ed25519_ix_index: auth.ed25519_ix_index,
        })
    );
}

#[test]
fn unwrap_external_call_commits_the_forwarder_segment() {
    let call = witness_external_call(unwrap_witness(u64::MAX as u128));
    assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
    assert_eq!(
        call.num_accounts,
        forwarder_client::FORWARDER_UNWRAP_NUM_ACCOUNTS
    );
    assert!(call.expected_output.is_empty());
    assert_eq!(call.output_mode, OutputMode::ReturnData);
    assert_eq!(call.instruction_data[0], OP_UNWRAP);
    assert_eq!(
        call.instruction_data,
        forwarder_client::encode_unwrap_forwarder_input(&SPL_TOKEN_MINT, u64::MAX, &SOLANA_ACCOUNT)
    );
}

#[test]
fn test_mint() {
    let mut resource_logic = TransferLogic::mint_resource_logic_with_wrap_auth(
        create_ephemeral_resource(),
        Digest::from_bytes(ACTION_TREE_ROOT),
        NullifierKey::from_bytes(NF_KEY_BYTES),
        label(),
        SOLANA_ACCOUNT,
        wrap_auth(),
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    verify(&proof).unwrap();
    assert_commits_external_call(&proof, &resource_logic);

    // A wrap must be triggered by a consumed resource.
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_burn() {
    let mut resource_logic = TransferLogic::burn_resource_logic(
        create_ephemeral_resource(),
        Digest::from_bytes(ACTION_TREE_ROOT),
        label(),
        SOLANA_ACCOUNT,
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    verify(&proof).unwrap();
    assert_commits_external_call(&proof, &resource_logic);

    // An unwrap must be triggered by a created resource.
    resource_logic.witness.is_consumed = true;
    resource_logic.witness.nf_key = Some(NullifierKey::from_bytes(NF_KEY_BYTES));
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_transfer() {
    let (auth_sk, _, encryption_sk, _) = owner_keys();
    let action_tree_root = Digest::from_bytes(ACTION_TREE_ROOT);
    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN, action_tree_root.as_bytes());

    let consumed_resource_logic = TransferLogic::consume_persistent_resource_logic(
        create_persistent_resource(),
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        owner_value(),
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
        owner_value(),
        label(),
        &mut OsRng,
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
}

/// The empty kind tree, which the adapter accepts whatever tree it stores.
static EMPTY_KIND_TREE: LazyLock<KindTree> = LazyLock::new(KindTree::empty);

/// The deployment facts of the action tests: a fixed commitment randomness
/// and the empty kind tree.
fn compliance_params() -> ComplianceParams<'static> {
    ComplianceParams {
        rcv: Scalar::ONE.to_bytes().to_vec(),
        kind_tree: &EMPTY_KIND_TREE,
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
    let (auth_sk, _, _, _) = owner_keys();
    let owner = Owner {
        value: owner_value(),
        nf_key: NullifierKey::from_bytes(NF_KEY_BYTES),
    };
    let kind_tree_root = EMPTY_KIND_TREE.root();

    let wrap = wrap::<TransferLogic>(
        label(),
        QUANTITY as u64,
        [5u8; 32],
        owner.clone(),
        [6u8; 32],
    )
    .unwrap();
    assert_eq!(wrap.deposit.created.value_ref, owner.value_ref());
    assert_eq!(wrap.deposit.created.quantity, QUANTITY);
    let auth = WrapAuth {
        user: SOLANA_ACCOUNT,
        info: wrap_auth(),
    };
    // base64 of a 32-byte hash: what the wallet signs.
    assert_eq!(
        wrap.signed_message(
            WRAP_NONCE,
            WRAP_DEADLINE,
            wrap.deposit.action_tree_root().unwrap()
        )
        .unwrap()
        .len(),
        44
    );
    let (_, discovery_pk) = random_keypair();
    let wrap_tx = wrap
        .action(auth, &discovery_pk, compliance_params(), &mut OsRng)
        .unwrap()
        .prove(ProofType::Succinct)
        .unwrap();
    anoma_rm_risc0::transaction::verify(&wrap_tx, kind_tree_root, JournalEncoding::Risc0Serde)
        .unwrap();
    assert_eq!(
        tags_of(&wrap_tx),
        vec![
            wrap.deposit
                .consumed
                .nullifier(&NullifierKey::default())
                .unwrap(),
            wrap.deposit.created.commitment()
        ]
    );

    let unwrap =
        unwrap::<TransferLogic>(label(), wrap.deposit.created, owner.clone(), SOLANA_ACCOUNT)
            .unwrap();
    assert_eq!(unwrap.created.quantity, QUANTITY);
    assert_eq!(
        unwrap.created.value_ref,
        calculate_value_ref_from_solana_account(&SOLANA_ACCOUNT)
    );
    let auth_sig = auth_sk.sign(
        AUTH_SIGNATURE_DOMAIN,
        unwrap.action_tree_root().unwrap().as_bytes(),
    );
    let unwrap_tx = unwrap
        .action(auth_sig, MerklePath::empty(), compliance_params())
        .unwrap()
        .prove(ProofType::Succinct)
        .unwrap();
    anoma_rm_risc0::transaction::verify(&unwrap_tx, kind_tree_root, JournalEncoding::Risc0Serde)
        .unwrap();
    assert_eq!(
        tags_of(&unwrap_tx),
        vec![
            wrap.deposit.created.nullifier(&owner.nf_key).unwrap(),
            unwrap.created.commitment()
        ]
    );
}

/// The digest of an action's witnesses as the provers receive them: the
/// compliance witness, then each logic witness, in order.
fn witnesses_digest(action: &TransferAction) -> Digest {
    let mut bytes = bincode::serialize(&action.compliance_witness).unwrap();
    for logic in &action.logic_witnesses {
        bytes.extend(bincode::serialize(logic).unwrap());
    }
    hash_bytes(&bytes)
}

/// The single-flow wrap and unwrap of the test owner, from fixed seeds, build
/// the action tree roots and witness bytes pinned here, which the guests and
/// every consumer of a wrap or unwrap rely on.
#[test]
fn single_flow_actions_are_pinned() {
    let (auth_sk, _, _, _) = owner_keys();
    let wrap = test_wrap();
    let wrap_action = wrap
        .action(
            WrapAuth {
                user: SOLANA_ACCOUNT,
                info: wrap_auth(),
            },
            &generate_public_key(&Scalar::from(ENCRYPTION_SK)),
            compliance_params(),
            &mut ChaCha20Rng::seed_from_u64(1),
        )
        .unwrap();
    let wrap_root = wrap.deposit.action_tree_root().unwrap();
    let wrap_digest = witnesses_digest(&wrap_action);
    println!("wrap: action tree root {wrap_root}, witnesses {wrap_digest}");

    let unwrap = unwrap::<TransferLogic>(
        label(),
        wrap.deposit.created,
        test_wrap().deposit.owner,
        SOLANA_ACCOUNT,
    )
    .unwrap();
    let unwrap_root = unwrap.action_tree_root().unwrap();
    let unwrap_action = unwrap
        .action(
            auth_sk.sign(AUTH_SIGNATURE_DOMAIN, unwrap_root.as_bytes()),
            MerklePath::empty(),
            compliance_params(),
        )
        .unwrap();
    let unwrap_digest = witnesses_digest(&unwrap_action);
    println!("unwrap: action tree root {unwrap_root}, witnesses {unwrap_digest}");

    assert_eq!(
        (wrap_root, wrap_digest, unwrap_root, unwrap_digest),
        (
            Digest::from_bytes(hex!(
                "737824905073cdaa593b1ebb79e35d433d152a6194b6aa0987a519cb1d729064"
            )),
            Digest::from_bytes(hex!(
                "2823324b789d47e176dac262687095f917c22bc14fc4c8633fba77e7adedc18e"
            )),
            Digest::from_bytes(hex!(
                "ea393da08b591e9249f601ff4477bf38b7464e893d0c77f404f5e52ef10e2e07"
            )),
            Digest::from_bytes(hex!(
                "b2036169556c7cecdf73324ff56e827099c9ee7d155f7018579a26b196d53c6c"
            )),
        ),
        "a single-flow action's root or witnesses changed"
    );
}

/// One action of an unwrap of the test wrap's resource to `SOLANA_ACCOUNT`
/// and a wrap of the same quantity from it, its resources in the order
/// `order` lists them by their index in [the unwrap's consumed, the unwrap's
/// created, the wrap's consumed, the wrap's created]: the compliance instance
/// and the logic witnesses keep that order, each created resource's nonce
/// derives from its index among the created resources, the owner and the
/// user sign the action's root, and the action proves and balances.
fn assert_multi_flow_action_keeps_the_order(order: [usize; 4]) {
    let (auth_sk, _, _, _) = owner_keys();
    let owner = test_wrap().deposit.owner;
    let wrapped = test_wrap().deposit.created;
    let unwrap = unwrap::<TransferLogic>(label(), wrapped, owner.clone(), SOLANA_ACCOUNT).unwrap();
    let wrap = wrap::<TransferLogic>(
        label(),
        QUANTITY as u64,
        [11u8; 32],
        owner.clone(),
        [12u8; 32],
    )
    .unwrap();

    let mut owner_signed = None;
    let mut user_signed = None;
    let (_, discovery_pk) = random_keypair();
    let mut rng = OsRng;
    let action = {
        let unwrap_parts = unwrap.parts(
            |root| {
                owner_signed = Some(root);
                auth_sk.sign(AUTH_SIGNATURE_DOMAIN, root.as_bytes())
            },
            MerklePath::empty(),
        );
        let wrap_parts = wrap.parts(
            |root| {
                user_signed = Some((root, wrap.signed_message(WRAP_NONCE, WRAP_DEADLINE, root)?));
                Ok(WrapAuth {
                    user: SOLANA_ACCOUNT,
                    info: wrap_auth(),
                })
            },
            &discovery_pk,
            &mut rng,
        );
        let mut parts = [
            Some(unwrap_parts.consumed),
            Some(unwrap_parts.created),
            Some(wrap_parts.consumed),
            Some(wrap_parts.created),
        ];
        let listed = order.map(|index| parts[index].take().unwrap());
        build(listed.into(), compliance_params()).unwrap()
    };

    let nullifiers = [
        wrapped.nullifier(&owner.nf_key).unwrap(),
        wrap.deposit
            .consumed
            .nullifier(&NullifierKey::default())
            .unwrap(),
    ];
    let created = [unwrap.created, wrap.deposit.created]
        .into_iter()
        .enumerate()
        .map(|(index, resource)| Resource {
            nonce: Resource::derive_nonce_from_nullifiers(index as u32, &nullifiers).unwrap(),
            ..resource
        })
        .collect::<Vec<_>>();
    let tags = [
        nullifiers[0],
        created[0].commitment(),
        nullifiers[1],
        created[1].commitment(),
    ];
    let resources = [wrapped, created[0], wrap.deposit.consumed, created[1]];
    let expected_tags = order.map(|index| tags[index]);
    let instance = compliance::constrain(&action.compliance_witness).unwrap();
    let instance_tags = instance.tags().collect::<Vec<_>>();
    println!("order {order:?}: compliance instance tags {instance_tags:?}");
    assert_eq!(
        instance_tags, expected_tags,
        "the compliance instance lists the resources in the caller's order"
    );

    let root = ActionTree::new(expected_tags.to_vec()).root().unwrap();
    assert_eq!(
        owner_signed,
        Some(root),
        "the owner signs the action's root"
    );
    let (user_root, message) = user_signed.unwrap();
    assert_eq!(user_root, root, "the user signs the action's root");
    assert_eq!(
        message,
        forwarder_client::WrapMessage {
            forwarder_id: FORWARDER_PROGRAM_ID,
            token_mint: SPL_TOKEN_MINT,
            amount: QUANTITY as u64,
            nonce: WRAP_NONCE,
            deadline: WRAP_DEADLINE,
            action_tree_root: root.into(),
        }
        .base64_digest(),
        "the wrap message names the action's root"
    );
    for (position, (logic, index)) in action.logic_witnesses.iter().zip(order).enumerate() {
        assert_eq!(
            (logic.witness.resource, logic.witness.is_consumed),
            (resources[index], index % 2 == 0),
            "logic witness {position} is of the resource listed there"
        );
        assert_eq!(
            logic.witness.action_tree_root, root,
            "logic witness {position} is of the action's root"
        );
    }

    let tx = action.prove(ProofType::Succinct).unwrap();
    anoma_rm_risc0::transaction::verify(&tx, EMPTY_KIND_TREE.root(), JournalEncoding::Risc0Serde)
        .unwrap();
    assert_eq!(tags_of(&tx), expected_tags);
}

#[test]
fn multi_flow_action_with_the_unwrap_first_keeps_its_order() {
    assert_multi_flow_action_keeps_the_order([0, 1, 2, 3]);
}

/// The wrap's consumed resource sits between the unwrap's resources, so the
/// order is the caller's, not one flow after another.
#[test]
fn multi_flow_action_with_interleaved_flows_keeps_its_order() {
    assert_multi_flow_action_keeps_the_order([0, 2, 1, 3]);
}

/// A wrap of the test owner with fixed nonces: its action differs between
/// calls only by the randomness the created resource's encryption draws.
fn test_wrap() -> Wrap {
    let owner = Owner {
        value: owner_value(),
        nf_key: NullifierKey::from_bytes(NF_KEY_BYTES),
    };
    wrap(label(), QUANTITY as u64, [5u8; 32], owner, [6u8; 32]).unwrap()
}

/// The signed message carries the SPL amount the circuit commits to, so a
/// quantity the circuit refuses as an SPL amount has no message either.
#[test]
fn wrap_signed_message_rejects_quantity_above_u64() {
    let mut wrap = test_wrap();
    wrap.deposit.consumed.quantity = u64::MAX as u128 + 1;
    let err = wrap
        .signed_message(
            WRAP_NONCE,
            WRAP_DEADLINE,
            Digest::from_bytes(ACTION_TREE_ROOT),
        )
        .expect_err("a quantity above u64::MAX must not be signed as an SPL amount");
    assert!(
        err.to_string().contains("exceeds u64::MAX"),
        "unexpected error: {err}"
    );
}

/// The witness of the test wrap's created resource, its randomness drawn
/// from `rng`.
fn created_witness(rng: &mut impl CryptoRngCore) -> TokenTransferWitness {
    let auth = WrapAuth {
        user: SOLANA_ACCOUNT,
        info: wrap_auth(),
    };
    let discovery_pk = generate_public_key(&Scalar::from(ENCRYPTION_SK));
    test_wrap()
        .action(auth, &discovery_pk, compliance_params(), rng)
        .unwrap()
        .logic_witnesses
        .swap_remove(1)
        .witness
}

/// The witness of the wrap's created resource, as the prover receives it,
/// and the instance it constrains to, which carries the encrypted payloads.
fn created_witness_and_instance(rng: &mut impl CryptoRngCore) -> (Vec<u8>, LogicInstance) {
    let witness = created_witness(rng);
    (
        bincode::serialize(&witness).unwrap(),
        witness.constrain().unwrap(),
    )
}

/// Asserts that two draws differ in every random input of the created
/// resource's witness and in both of its ciphertexts.
fn assert_fresh_randomness(first: &mut impl CryptoRngCore, second: &mut impl CryptoRngCore) {
    let first = created_witness(first);
    let second = created_witness(second);
    let first_encryption = first.encryption_info.as_ref().unwrap();
    let second_encryption = second.encryption_info.as_ref().unwrap();
    assert!(
        first_encryption.sender_sk != second_encryption.sender_sk,
        "the sender keys must differ"
    );
    assert_ne!(
        first_encryption.encryption_nonce, second_encryption.encryption_nonce,
        "the resource payload nonces must differ"
    );
    assert_ne!(
        first_encryption.discovery_ciphertext, second_encryption.discovery_ciphertext,
        "the discovery ciphertexts must differ"
    );
    let first_payload = first.constrain().unwrap().app_data.resource_payload;
    let second_payload = second.constrain().unwrap().app_data.resource_payload;
    assert_ne!(
        first_payload[0].blob, second_payload[0].blob,
        "the resource payload ciphertexts must differ"
    );
}

#[test]
fn wrap_action_is_reproducible_from_a_seed() {
    let (first_witness, first_instance) =
        created_witness_and_instance(&mut ChaCha20Rng::seed_from_u64(1));
    let (second_witness, second_instance) =
        created_witness_and_instance(&mut ChaCha20Rng::seed_from_u64(1));
    assert_eq!(
        first_witness, second_witness,
        "the created resource's witness must be a function of the seed"
    );
    assert_eq!(
        first_instance, second_instance,
        "the created resource's encrypted payloads must be a function of the seed"
    );
}

#[test]
fn wrap_actions_from_different_seeds_differ() {
    assert_fresh_randomness(
        &mut ChaCha20Rng::seed_from_u64(1),
        &mut ChaCha20Rng::seed_from_u64(2),
    );
}

#[test]
fn wrap_actions_from_os_rng_differ() {
    assert_fresh_randomness(&mut OsRng, &mut OsRng);
}
