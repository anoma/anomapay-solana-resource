//! Op-code constants and forwarder input encoders for the v2 transfer resource.
//!
//! `Wrap` / `Unwrap` reuse the v1 op codes and encoders owned by
//! `anoma-pa-solana-client` (re-exported through [`transfer_witness::call_type`]).
//! v2 only adds the **migrate** call: the `OP_MIGRATE` op byte and
//! `encode_migrate_forwarder_input`, which mirror the byte-layout conventions of
//! the v1 wrap/unwrap encoders.

use serde::{Deserialize, Serialize};

// Re-export the v1 op codes and encoders so `call_type_v2` is the single entry
// point for v2 callers.
pub use transfer_witness::call_type::{
    OP_UNWRAP, OP_WRAP, encode_unwrap_forwarder_input, encode_wrap_forwarder_input,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallTypeV2 {
    Wrap,
    Unwrap,
    Migrate,
}

/// Op byte prepended to migrate-shaped forwarder instruction data.
///
/// `OP_WRAP` (0) and `OP_UNWRAP` (1) are owned by `anoma-pa-solana-client`;
/// `OP_MIGRATE` continues that op space for the v2 forwarder.
pub const OP_MIGRATE: u8 = 2;

/// Number of accounts in a migrate call's CPI segment (including the forwarder
/// program account at position 0). The v1 wrap/unwrap calls use 12 / 9; migrate
/// is a new instruction whose account layout is fixed by the deployed v2
/// forwarder.
///
/// NOTE: this value MUST match the migrate instruction of the on-chain v2
/// forwarder. It is provisional until that program is finalized; revisit before
/// shipping migration to a live network.
pub const MIGRATE_FORWARDER_NUM_ACCOUNTS: u8 = 9;

/// Build the migrate forwarder instruction data.
///
/// Layout (mirrors the v1 wrap/unwrap shape — op byte, 32-byte fields, LE
/// amount): `op(1) + token_mint(32) + amount_le(8) + nullifier(32) +
/// root_v1(32) + logic_ref_v1(32) + forwarder_v1(32)` = 169 bytes.
///
/// - `nullifier` is the nullifier of the v1 resource being migrated.
/// - `commitment_tree_root` is the v1 commitment-tree root that witnesses the
///   migrated resource's existence.
/// - `migrate_resource_logic_ref` is the v1 resource's logic reference.
/// - `migrate_resource_forwarder_id` is the **v1** forwarder program id encoded
///   in the migrated resource's label.
pub fn encode_migrate_forwarder_input(
    token_mint: &[u8; 32],
    amount: u64,
    nullifier: &[u8],
    commitment_tree_root: &[u8],
    migrate_resource_logic_ref: &[u8],
    migrate_resource_forwarder_id: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(169);
    buf.push(OP_MIGRATE);
    buf.extend_from_slice(token_mint);
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(&pad_to_32(nullifier));
    buf.extend_from_slice(&pad_to_32(commitment_tree_root));
    buf.extend_from_slice(&pad_to_32(migrate_resource_logic_ref));
    buf.extend_from_slice(migrate_resource_forwarder_id);
    buf
}

fn pad_to_32(input: &[u8]) -> [u8; 32] {
    assert!(
        input.len() <= 32,
        "input too long for 32-byte field: {} bytes",
        input.len()
    );
    let mut out = [0u8; 32];
    out[..input.len()].copy_from_slice(input);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_input_length_is_169_bytes() {
        let bytes = encode_migrate_forwarder_input(
            &[1u8; 32], 42, &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32],
        );
        assert_eq!(bytes.len(), 169);
        assert_eq!(bytes[0], OP_MIGRATE);
    }
}
