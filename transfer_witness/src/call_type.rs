//! Op-code constants and forwarder input encoders for the transfer resource.
//!
//! The op codes and instruction-data encoders are owned by
//! `anoma-pa-solana-client`, so the circuit and the on-chain forwarder agree
//! byte for byte. Only `CallType` and the migrate account count live here.

use serde::{Deserialize, Serialize};

pub use anoma_pa_solana_client::external_call::{
    OP_MIGRATE, OP_UNWRAP, OP_WRAP, encode_migrate_forwarder_input, encode_unwrap_forwarder_input,
    encode_wrap_forwarder_input,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Wrap,
    Unwrap,
    Migrate,
}

/// Number of accounts in a migrate call's CPI segment (including the forwarder
/// program account at position 0). The wrap/unwrap calls use 12 / 9; migrate
/// is a new instruction whose account layout is fixed by the deployed
/// forwarder.
///
/// NOTE: this value MUST match the migrate instruction of the on-chain
/// forwarder. It is provisional until that program is finalized; revisit before
/// shipping migration to a live network.
pub const MIGRATE_FORWARDER_NUM_ACCOUNTS: u8 = 9;
