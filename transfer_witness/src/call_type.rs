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
pub const WRAP_SEGMENT_NUM_ACCOUNTS: u8 = 8;

/// Accounts in an unwrap call's CPI segment, the forwarder program account
/// first: `[forwarder_program, config_pda, ix_sysvar, escrow_ata,
/// recipient_ata, escrow_pda, token_program]`.
pub const UNWRAP_SEGMENT_NUM_ACCOUNTS: u8 = 7;
