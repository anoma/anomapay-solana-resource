//! Op-code constants and forwarder input encoders for the v2 transfer resource.
//!
//! All op codes and instruction-data encoders are owned by
//! `anoma-pa-solana-client` so the circuit and the on-chain forwarder agree
//! byte-for-byte. `Wrap` / `Unwrap` are re-exported through
//! [`transfer_witness::call_type`]; the v2-only `Migrate` op code and encoder
//! come from the same client crate. Only `CallTypeV2` and the migrate account
//! count live here.

use serde::{Deserialize, Serialize};

// v1 op codes and encoders, re-exported so `call_type_v2` is the single entry
// point for v2 callers.
pub use transfer_witness::call_type::{
    OP_UNWRAP, OP_WRAP, encode_unwrap_forwarder_input, encode_wrap_forwarder_input,
};

// The migrate op code and encoder are owned by `anoma-pa-solana-client`; sourced
// here so both this circuit and the on-chain forwarder agree byte-for-byte.
// Layout: `op(1) + token_mint(32) + amount_le(8) + nullifier(32) +
// commitment_tree_root(32) + logic_ref_v1(32) + forwarder_v1(32)` = 169 bytes.
pub use anoma_pa_solana_client::external_call::{OP_MIGRATE, encode_migrate_forwarder_input};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallTypeV2 {
    Wrap,
    Unwrap,
    Migrate,
}

/// Number of accounts in a migrate call's CPI segment (including the forwarder
/// program account at position 0). The v1 wrap/unwrap calls use 12 / 9; migrate
/// is a new instruction whose account layout is fixed by the deployed v2
/// forwarder.
///
/// NOTE: this value MUST match the migrate instruction of the on-chain v2
/// forwarder. It is provisional until that program is finalized; revisit before
/// shipping migration to a live network.
pub const MIGRATE_FORWARDER_NUM_ACCOUNTS: u8 = 9;
