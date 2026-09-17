//! The forwarder call an ephemeral resource triggers, and the size of the
//! account segment the settlement transaction must carry for it. The op codes
//! and input encoders are owned by `anoma-pa-solana-client`, so the circuit and
//! the on-chain forwarder agree byte for byte.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Wrap,
    Unwrap,
}

/// Accounts in a wrap call's CPI segment, the forwarder program account first:
/// `[forwarder_program, config_pda, ix_sysvar, user_ata, escrow_ata,
/// escrow_pda, nonce_bitmap_pda, token_program]`.
///
/// `anoma-pa-solana-client`'s `FORWARDER_WRAP_NUM_ACCOUNTS` still describes the
/// V1 forwarder's 12-account segment its builders emit; anoma/dos-pm#76 moves
/// the client to this segment, after which this constant is taken from there.
pub const WRAP_SEGMENT_NUM_ACCOUNTS: u8 = 8;

/// Accounts in an unwrap call's CPI segment, the forwarder program account
/// first: `[forwarder_program, config_pda, ix_sysvar, escrow_ata,
/// recipient_ata, escrow_pda, token_program]`.
///
/// The client's `FORWARDER_UNWRAP_NUM_ACCOUNTS` (9) is the V1 segment until
/// anoma/dos-pm#76 lands.
pub const UNWRAP_SEGMENT_NUM_ACCOUNTS: u8 = 7;
