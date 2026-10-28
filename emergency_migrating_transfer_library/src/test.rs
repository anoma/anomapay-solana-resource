// Circuit tests for the emergency-migrating logic, against the committed
// guest ELF (`EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF`). Proving is slow
// without `RISC0_DEV_MODE=1`; set it when running these locally.
use anoma_pa_solana_client::external_call::{OutputMode, SolanaExternalCall};
use anoma_rm_risc0::{
    Digest,
    kind_table::KindTable,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::{JournalEncoding, ProofType},
    resource::Resource,
    transaction::Transaction,
    utils::words_to_bytes,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::random_keypair,
};
use anomapay_spl_token_forwarder_client::{
    MigrateEntry as ForwarderMigrateEntry, MigrateInput, encode_migrate_forwarder_input,
    forwarder_migrate_num_accounts,
    generated::emergency_migrating_spl_token_forwarder::constants::OP_MIGRATE,
};
use emergency_migrating_transfer_witness::{
    EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN, MigrateEntry, wire,
};
use k256::Scalar;
use rand_core::OsRng;
use std::sync::LazyLock;
use transfer_library::{
    TOKEN_TRANSFER_ID,
    action::{ComplianceParams, Owner, unwrap},
};
use transfer_witness::{LabelInfo, ValueInfo, calculate_label_ref};

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
            value_ref: owner.value_ref(),
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
}

/// The guest declares the forwarder's migrate format itself
/// (`emergency_migrating_transfer_witness::wire`), so no client release
/// reaches its VK; it is the forwarder client's byte for byte, and so is the
/// migration segment's account count for every batch size the client
/// accepts and the first it refuses.
#[test]
fn the_guests_wire_formats_are_the_clients() {
    for count in [0u8, 1, 3] {
        let entries: Vec<_> = (0..count)
            .map(|i| {
                (
                    [0x10 + i; 32],
                    [0x20 + i; 32],
                    [0x30 + i; 32],
                    [0x40 + i; 32],
                )
            })
            .collect();
        let guest = wire::encode_migrate_forwarder_input(&wire::MigrateInput {
            token_mint: SPL_TOKEN_MINT,
            quantity: 0x0102_0304_0506_0708,
            entries: entries
                .iter()
                .map(
                    |&(nullifier, commitment_tree_root, vulnerable_logic_ref, forwarder)| {
                        wire::MigrateEntry {
                            nullifier,
                            commitment_tree_root,
                            vulnerable_logic_ref,
                            forwarder,
                        }
                    },
                )
                .collect(),
        });
        let client = encode_migrate_forwarder_input(&MigrateInput {
            token_mint: SPL_TOKEN_MINT,
            quantity: 0x0102_0304_0506_0708,
            entries: entries
                .iter()
                .map(
                    |&(nullifier, commitment_tree_root, vulnerable_logic_ref, forwarder)| {
                        ForwarderMigrateEntry {
                            nullifier,
                            commitment_tree_root,
                            vulnerable_logic_ref,
                            forwarder,
                        }
                    },
                )
                .collect(),
        });
        println!("migrate input of {count} entries: guest {guest:02x?}, client {client:02x?}");
        assert_eq!(guest, client, "the migrate input of {count} entries");
    }
    assert_eq!(wire::OP_MIGRATE, OP_MIGRATE, "OP_MIGRATE");

    let mut entries = 0;
    loop {
        let guest = wire::forwarder_migrate_num_accounts(entries);
        let client = forwarder_migrate_num_accounts(entries);
        assert_eq!(
            guest, client,
            "the segment of a migration of {entries} entries"
        );
        if client.is_none() {
            println!("the client refuses a migration of {entries} entries, and so does the guest");
            break;
        }
        entries += 1;
    }
    assert_eq!(
        wire::forwarder_migrate_num_accounts(usize::MAX),
        forwarder_migrate_num_accounts(usize::MAX),
        "the segment of a migration of usize::MAX entries"
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
    let created = migration.deposit.created;
    assert_eq!(created.quantity, 1000);
    assert_eq!(created.logic_ref, EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID);
    let auth_sig = auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        migration.deposit.action_tree_root().unwrap().as_bytes(),
    );
    let tx = migration
        .action(
            auth_sig,
            &random_keypair().1,
            compliance_params(),
            &mut OsRng,
        )
        .unwrap()
        .prove(ProofType::Succinct)
        .unwrap();
    verify(&tx);

    let trigger = &tx.actions.as_ref().unwrap()[0].logic_verifier_inputs[0];
    assert_eq!(trigger.app_data.external_payload.len(), 1);
    let call =
        SolanaExternalCall::decode(words_to_bytes(&trigger.app_data.external_payload[0].blob))
            .unwrap();
    assert_eq!(call.program_id, FORWARDER_PROGRAM_ID);
    assert_eq!(
        call.num_accounts,
        forwarder_migrate_num_accounts(2).unwrap()
    );
    assert!(call.expected_output.is_empty());
    assert_eq!(call.output_mode, OutputMode::ReturnData);
    assert_eq!(
        call.instruction_data,
        encode_migrate_forwarder_input(&MigrateInput {
            token_mint: SPL_TOKEN_MINT,
            quantity: 1000,
            entries: entries
                .iter()
                .map(|entry| ForwarderMigrateEntry {
                    nullifier: entry.resource.nullifier(&entry.nf_key).unwrap().into(),
                    commitment_tree_root: entry.path.root(&entry.resource.commitment()).into(),
                    vulnerable_logic_ref: TOKEN_TRANSFER_ID.into(),
                    forwarder: entry.forwarder_program_id,
                })
                .collect(),
        })
    );

    let unwrap =
        unwrap::<EmergencyMigratingTransferLogic>(label(), created, new_owner.clone(), RECIPIENT)
            .unwrap();
    assert_eq!(
        unwrap.created.logic_ref,
        EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID
    );
    let auth_sig = auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        unwrap.action_tree_root().unwrap().as_bytes(),
    );
    verify(
        &unwrap
            .action(auth_sig, MerklePath::empty(), compliance_params())
            .unwrap()
            .prove(ProofType::Succinct)
            .unwrap(),
    );
}

/// An unwrap through this logic refuses a resource of the transfer logic,
/// whose proof this logic's guest would not verify.
#[test]
fn an_unwrap_refuses_a_resource_of_another_logic() {
    let auth_sk = AuthoritySigningKey::from_bytes(&[7u8; 32]).unwrap();
    let old_owner = owner(&auth_sk, 3);
    let entry = transfer_logic_resource(
        &old_owner,
        FORWARDER_PROGRAM_ID,
        400,
        2,
        MerklePath::empty(),
    );
    let err =
        unwrap::<EmergencyMigratingTransferLogic>(label(), entry.resource, old_owner, RECIPIENT)
            .err()
            .expect("the unwrap refuses the resource");
    assert!(
        err.to_string().contains("not of the unwrap's logic"),
        "unexpected error: {err}"
    );
}
