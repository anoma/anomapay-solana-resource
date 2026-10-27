//! The adapter's external call and the SPL token forwarder's wrap and unwrap
//! inputs, as this circuit commits them. They are declared here rather than
//! taken from the adapter's and the forwarder's clients, as the EVM ERC20
//! resource declares its forwarder's input itself: cargo derives a crate's
//! symbols from its source, so a client release would otherwise change this
//! guest's VK. `transfer_library`'s tests check them against the clients.

use serde::Serialize;

/// An external call of the adapter: the forwarder program, its instruction
/// data, the output it must return and the accounts of its CPI segment.
#[derive(Serialize)]
pub struct SolanaExternalCall {
    pub program_id: [u8; 32],
    pub instruction_data: Vec<u8>,
    pub expected_output: Vec<u8>,
    pub output_mode: OutputMode,
    /// The accounts of the call's CPI segment, the forwarder's at position 0.
    pub num_accounts: u8,
}

/// How the adapter reads an external call's output.
#[derive(Serialize)]
pub enum OutputMode {
    /// Solana `return_data`.
    ReturnData,
}

impl SolanaExternalCall {
    /// The call's bincode encoding, which the adapter decodes from the
    /// external payload.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SolanaExternalCall serialization should not fail")
    }
}

/// The op byte of a wrap's instruction data.
pub const OP_WRAP: u8 = 0;

/// The op byte of an unwrap's instruction data.
pub const OP_UNWRAP: u8 = 1;

/// The accounts every forwarder CPI segment starts with: the forwarder, its
/// config, the instructions sysvar, the event authority and the forwarder
/// again.
pub const FORWARDER_SEGMENT_HEAD_NUM_ACCOUNTS: u8 = 5;

/// The accounts of a wrap's segment: the head, the user's and the escrow's
/// token accounts, the escrow authority, the nonce bitmap and the token
/// program.
pub const FORWARDER_WRAP_NUM_ACCOUNTS: u8 = FORWARDER_SEGMENT_HEAD_NUM_ACCOUNTS + 5;

/// The accounts of an unwrap's segment: the head, the escrow's and the
/// recipient's token accounts, the escrow authority and the token program.
pub const FORWARDER_UNWRAP_NUM_ACCOUNTS: u8 = FORWARDER_SEGMENT_HEAD_NUM_ACCOUNTS + 4;

/// A wrap's input: the forwarder escrows `amount` of `token_mint` from
/// `user`'s token account, authorized by the user's ed25519 signature, which
/// the ed25519 instruction at `ed25519_ix_index` verifies.
pub struct WrapInput {
    pub token_mint: [u8; 32],
    pub amount: u64,
    pub user: [u8; 32],
    pub nonce: u64,
    pub deadline: i64,
    pub action_tree_root: [u8; 32],
    pub signature: [u8; 64],
    pub ed25519_ix_index: u8,
}

/// The 186-byte instruction data of the wrap `input`: `op(1) +
/// token_mint(32) + amount_le(8) + user(32) + nonce_le(8) +
/// deadline_le_i64(8) + action_tree_root(32) + signature(64) +
/// ed25519_ix_index(1)`.
pub fn encode_wrap_forwarder_input(input: &WrapInput) -> Vec<u8> {
    let mut buf = Vec::with_capacity(186);
    buf.push(OP_WRAP);
    buf.extend_from_slice(&input.token_mint);
    buf.extend_from_slice(&input.amount.to_le_bytes());
    buf.extend_from_slice(&input.user);
    buf.extend_from_slice(&input.nonce.to_le_bytes());
    buf.extend_from_slice(&input.deadline.to_le_bytes());
    buf.extend_from_slice(&input.action_tree_root);
    buf.extend_from_slice(&input.signature);
    buf.push(input.ed25519_ix_index);
    buf
}

/// The 73-byte instruction data of an unwrap of `amount` of `token_mint` to
/// `recipient`: `op(1) + token_mint(32) + amount_le(8) + recipient(32)`.
pub fn encode_unwrap_forwarder_input(
    token_mint: &[u8; 32],
    amount: u64,
    recipient: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(73);
    buf.push(OP_UNWRAP);
    buf.extend_from_slice(token_mint);
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(recipient);
    buf
}
