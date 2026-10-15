// Circuit tests for the emergency-migrating logic, against the committed
// guest ELF (`EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF`). Proving is slow
// without `RISC0_DEV_MODE=1`; set it when running these locally.
use anoma_pa_solana_client::external_call::SolanaExternalCall;
use anoma_rm_risc0::{
    Digest,
    delta_proof::DeltaWitness,
    error::ArmError,
    kind_table::KindTable,
    logic_proof::{LogicProver, get_instance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::{JournalEncoding, ProofType},
    resource::Resource,
    transaction::{Delta, Transaction},
    utils::words_to_bytes,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::random_keypair,
};
use anomapay_spl_token_forwarder_client::{ForwarderInput, decode_forwarder_input};
use emergency_migrating_transfer_witness::{
    EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN, LogicCircuit, MigrateEntry,
};
use k256::Scalar;
use rand_core::OsRng;
use std::sync::LazyLock;
use transfer_library::{
    TOKEN_TRANSFER_ID,
    action::{ComplianceParams, Owner, TransferAction, unwrap},
};
use transfer_witness::{LabelInfo, ValueInfo, calculate_label_ref, calculate_persistent_value_ref};

use crate::action::migrate;
use crate::{
    EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF, EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID,
    EmergencyMigratingTransferLogic,
};

const FORWARDER_PROGRAM_ID: [u8; 32] = [10u8; 32];
const LEGACY_FORWARDER_PROGRAM_ID: [u8; 32] = [11u8; 32];
const SPL_TOKEN_MINT: [u8; 32] = [1u8; 32];
const RECIPIENT: [u8; 32] = [2u8; 32];

static EMPTY_KIND_TABLE: LazyLock<KindTable> = LazyLock::new(KindTable::empty);

fn label() -> LabelInfo {
    LabelInfo {
        forwarder_program_id: FORWARDER_PROGRAM_ID,
        spl_token_mint: SPL_TOKEN_MINT,
    }
}

fn compliance_params() -> ComplianceParams<'static> {
    ComplianceParams {
        rcv: Scalar::ONE.to_bytes().to_vec(),
        kind_table: &EMPTY_KIND_TABLE,
    }
}

fn owner(auth_sk: &AuthoritySigningKey, nf_key: u8) -> Owner {
    Owner {
        value: ValueInfo {
            auth_pk: AuthorityVerifyingKey::from_signing_key(auth_sk),
            encryption_pk: random_keypair().1,
        },
        nf_key: NullifierKey::from_bytes([nf_key; 32]),
    }
}

/// `owner`'s resource of the transfer logic under `forwarder`, at the
/// commitment-tree position `path`.
fn transfer_logic_resource(
    owner: &Owner,
    forwarder: [u8; 32],
    quantity: u128,
    nonce: u8,
    path: MerklePath,
) -> MigrateEntry {
    MigrateEntry {
        resource: Resource {
            logic_ref: TOKEN_TRANSFER_ID,
            label_ref: calculate_label_ref(&forwarder, &SPL_TOKEN_MINT),
            value_ref: calculate_persistent_value_ref(&owner.value),
            quantity,
            is_ephemeral: false,
            nonce: [nonce; 32],
            nk_commitment: owner.nf_key.commit(),
            ..Default::default()
        },
        nf_key: owner.nf_key.clone(),
        path,
        value_info: owner.value.clone(),
        forwarder_program_id: forwarder,
    }
}

/// Proves the action in-process and wraps it in a balanced transaction.
fn prove<L: LogicProver>(action: &TransferAction<L>) -> Transaction {
    let compliance_unit =
        anoma_rm_risc0::compliance_unit::create(&action.compliance_witness, ProofType::Succinct)
            .unwrap();
    let consumed = action.consumed_logic.prove(ProofType::Succinct).unwrap();
    let created = action.created_logic.prove(ProofType::Succinct).unwrap();
    let action = anoma_rm_risc0::action::new(compliance_unit, vec![consumed, created]).unwrap();
    let delta_witness = DeltaWitness::from_bytes(&compliance_params().rcv).unwrap();
    let tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    anoma_rm_risc0::transaction::generate_delta_proof(tx).unwrap()
}

fn verify(tx: &Transaction) {
    anoma_rm_risc0::transaction::verify(tx, EMPTY_KIND_TABLE.root(), JournalEncoding::Risc0Serde)
        .unwrap();
}

#[test]
fn image_id_matches_the_embedded_guest() {
    assert_eq!(
        risc0_zkvm::compute_image_id(EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF).unwrap(),
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID
    );
    assert_eq!(
        EmergencyMigratingTransferLogic::verifying_key(),
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID
    );
}

/// A migration of two transfer-logic resources, one under the legacy
/// forwarder and one under this one, proves against the embedded guest,
/// balances, and commits the forwarder's migrate call over both; the
/// migrated resource then unwraps through this logic.
#[test]
fn migration_proves_balances_and_its_resource_unwraps() {
    let auth_sk = AuthoritySigningKey::from_bytes(&[7u8; 32]).unwrap();
    let old_owner = owner(&auth_sk, 3);
    let entries = vec![
        transfer_logic_resource(
            &old_owner,
            LEGACY_FORWARDER_PROGRAM_ID,
            600,
            1,
            MerklePath::from_path(&[(Digest::from_bytes([4u8; 32]), true)]),
        ),
        transfer_logic_resource(
            &old_owner,
            FORWARDER_PROGRAM_ID,
            400,
            2,
            MerklePath::empty(),
        ),
    ];
    let new_owner = owner(&auth_sk, 5);

    let migration = migrate(
        label(),
        entries.clone(),
        [8u8; 32],
        new_owner.clone(),
        [9u8; 32],
    )
    .unwrap();
    assert_eq!(migration.created.quantity, 1000);
    assert_eq!(
        migration.created.logic_ref,
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID
    );
    let auth_sig = auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        migration.action_tree_root().unwrap().as_bytes(),
    );
    let action = migration
        .action(
            auth_sig,
            &random_keypair().1,
            compliance_params(),
            &mut OsRng,
        )
        .unwrap();
    let trigger_proof = action.consumed_logic.prove(ProofType::Succinct).unwrap();
    let external_payload = get_instance(&trigger_proof)
        .unwrap()
        .app_data
        .external_payload;
    assert_eq!(external_payload.len(), 1);
    let call = SolanaExternalCall::decode(words_to_bytes(&external_payload[0].blob)).unwrap();
    assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
    let ForwarderInput::Migrate(input) = decode_forwarder_input(&call.instruction_data).unwrap()
    else {
        panic!("the trigger commits a migrate call");
    };
    assert_eq!(input.token_mint, SPL_TOKEN_MINT);
    assert_eq!(input.quantity, 1000);
    for (committed, entry) in input.entries.iter().zip(&entries) {
        assert_eq!(
            committed.nullifier,
            <[u8; 32]>::from(entry.resource.nullifier(&entry.nf_key).unwrap())
        );
        assert_eq!(
            committed.commitment_tree_root,
            <[u8; 32]>::from(entry.path.root(&entry.resource.commitment()))
        );
        assert_eq!(
            committed.vulnerable_logic_ref,
            <[u8; 32]>::from(TOKEN_TRANSFER_ID)
        );
        assert_eq!(committed.forwarder, entry.forwarder_program_id);
    }
    assert_eq!(input.entries.len(), entries.len());
    verify(&prove(&action));

    let unwrap = unwrap(label(), migration.created, new_owner.clone(), RECIPIENT).unwrap();
    assert_eq!(
        unwrap.created.logic_ref,
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID
    );
    let auth_sig = auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        unwrap.action_tree_root().unwrap().as_bytes(),
    );
    let unwrap_action = unwrap
        .action(auth_sig, MerklePath::empty(), compliance_params())
        .unwrap()
        .into_logic::<EmergencyMigratingTransferLogic>();
    verify(&prove(&unwrap_action));
}

/// A migration's batch is signed for this logic: the transfer logic's
/// signature of the same root does not authorize it.
#[test]
fn migration_refuses_a_signature_for_the_transfer_logic() {
    let auth_sk = AuthoritySigningKey::from_bytes(&[7u8; 32]).unwrap();
    let old_owner = owner(&auth_sk, 3);
    let migration = migrate(
        label(),
        vec![transfer_logic_resource(
            &old_owner,
            LEGACY_FORWARDER_PROGRAM_ID,
            600,
            1,
            MerklePath::empty(),
        )],
        [8u8; 32],
        owner(&auth_sk, 5),
        [9u8; 32],
    )
    .unwrap();
    let auth_sig = auth_sk.sign(
        transfer_witness::AUTH_SIGNATURE_DOMAIN,
        migration.action_tree_root().unwrap().as_bytes(),
    );
    let action = migration
        .action(
            auth_sig,
            &random_keypair().1,
            compliance_params(),
            &mut OsRng,
        )
        .unwrap();
    assert!(matches!(
        action.consumed_logic.witness.constrain(),
        Err(ArmError::InvalidSignature)
    ));
    assert!(action.consumed_logic.prove(ProofType::Succinct).is_err());
}
