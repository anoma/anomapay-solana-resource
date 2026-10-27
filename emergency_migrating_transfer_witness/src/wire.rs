//! The emergency-migrating SPL token forwarder's migrate input, as this
//! circuit commits it, declared here rather than taken from the forwarder's
//! client for the reason `transfer_witness::wire` gives.
//! `emergency_migrating_transfer_library`'s tests check it against the
//! client.

use transfer_witness::wire::FORWARDER_SEGMENT_HEAD_NUM_ACCOUNTS;

/// The op byte of a migration's instruction data.
pub const OP_MIGRATE: u8 = 2;

/// A migration's input: the forwarder records the entries' nullifiers, which
/// moves no tokens. `quantity` is the batch's total.
pub struct MigrateInput {
    pub token_mint: [u8; 32],
    pub quantity: u64,
    pub entries: Vec<MigrateEntry>,
}

/// One resource of a migration batch.
pub struct MigrateEntry {
    pub nullifier: [u8; 32],
    /// The commitment tree root the resource is proven against.
    pub commitment_tree_root: [u8; 32],
    /// The resource's logic ref, which the forwarder lists as vulnerable.
    pub vulnerable_logic_ref: [u8; 32],
    /// The forwarder in the resource's label.
    pub forwarder: [u8; 32],
}

/// The instruction data of the migration `input`: `op(1) + token_mint(32) +
/// quantity_le(8) + entry_count_le_u32(4)`, then per entry `nullifier(32) +
/// commitment_tree_root(32) + vulnerable_logic_ref(32) + forwarder(32)`.
pub fn encode_migrate_forwarder_input(input: &MigrateInput) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32 + 8 + 4 + 128 * input.entries.len());
    buf.push(OP_MIGRATE);
    buf.extend_from_slice(&input.token_mint);
    buf.extend_from_slice(&input.quantity.to_le_bytes());
    let count = u32::try_from(input.entries.len()).expect("a batch holds fewer than 2^32 entries");
    buf.extend_from_slice(&count.to_le_bytes());
    for entry in &input.entries {
        buf.extend_from_slice(&entry.nullifier);
        buf.extend_from_slice(&entry.commitment_tree_root);
        buf.extend_from_slice(&entry.vulnerable_logic_ref);
        buf.extend_from_slice(&entry.forwarder);
    }
    buf
}

/// The accounts of the segment of a migration of `entries` resources: the
/// head, the adapter's state and the vulnerable logic refs, then three per
/// entry. None when it exceeds the `u8` an external call commits.
pub fn forwarder_migrate_num_accounts(entries: usize) -> Option<u8> {
    let before_entries = usize::from(FORWARDER_SEGMENT_HEAD_NUM_ACCOUNTS) + 2;
    u8::try_from(entries.checked_mul(3)?.checked_add(before_entries)?).ok()
}
