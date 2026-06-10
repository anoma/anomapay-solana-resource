//! Wire-level types and helpers for the PA's external-call subsystem.
//!
//! The PA carries an opaque `Vec<u8>` per external call in the ARM transaction's
//! external_payload section. Off-chain we serialize/deserialize via `bincode`;
//! on-chain the PA reads the same shape. PA and integrators must agree byte-for-byte.

use serde::{Deserialize, Serialize};

/// Solana-specific external call structure.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SolanaExternalCall {
    /// Forwarder program ID (32 bytes).
    pub program_id: [u8; 32],
    /// The forwarder's instruction data (op byte + input layout).
    pub instruction_data: Vec<u8>,
    /// Expected return-data bytes (committed in the proof).
    pub expected_output: Vec<u8>,
    /// How the PA reads the forwarder's output.
    pub output_mode: OutputMode,
    /// Number of accounts in this call's CPI segment (including the forwarder
    /// program account at position 0). Committed in the proof so segment
    /// boundaries are unambiguous.
    pub num_accounts: u8,
}

/// How the PA reads an external call's output.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum OutputMode {
    /// Read output from Solana `return_data`.
    ReturnData,
}

impl SolanaExternalCall {
    /// Bincode-serialize this call. Used to embed in the ARM transaction's
    /// external_payload section.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SolanaExternalCall serialization should not fail")
    }

    /// Bincode-deserialize from the ARM transaction's external_payload blob.
    pub fn decode(bytes: &[u8]) -> Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(bytes)
    }
}

// ---- Forwarder op codes and input encoders ---------------------------------

/// Op byte prepended to `WrapInput`-shaped instruction data.
pub const OP_WRAP: u8 = 0;

/// Op byte prepended to `UnwrapInput`-shaped instruction data.
pub const OP_UNWRAP: u8 = 1;

/// Build the 186-byte forwarder instruction data for a wrap.
///
/// Layout: `op(1) + token_mint(32) + amount_le(8) + user(32) + nonce_le(8) +
/// deadline_le_i64(8) + action_tree_root(32) + signature(64) + ed25519_ix_index(1)`.
///
/// `deadline` is signed i64 to match the forwarder's `WrapInput::deadline: i64`.
#[allow(clippy::too_many_arguments)]
pub fn encode_wrap_forwarder_input(
    token_mint: &[u8],
    amount: u64,
    user: &[u8],
    nonce: u64,
    deadline: i64,
    action_tree_root: &[u8],
    signature: &[u8],
    ed25519_ix_index: u8,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(186);
    buf.push(OP_WRAP);
    buf.extend_from_slice(&pad_to_32(token_mint));
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(&pad_to_32(user));
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&deadline.to_le_bytes());
    buf.extend_from_slice(&pad_to_32(action_tree_root));
    buf.extend_from_slice(&pad_to_64(signature));
    buf.push(ed25519_ix_index);
    buf
}

/// Build the 73-byte forwarder instruction data for an unwrap.
///
/// Layout: `op(1) + token_mint(32) + amount_le(8) + recipient(32)`.
pub fn encode_unwrap_forwarder_input(token_mint: &[u8], amount: u64, recipient: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(73);
    buf.push(OP_UNWRAP);
    buf.extend_from_slice(&pad_to_32(token_mint));
    buf.extend_from_slice(&amount.to_le_bytes());
    buf.extend_from_slice(&pad_to_32(recipient));
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

fn pad_to_64(input: &[u8]) -> [u8; 64] {
    assert!(
        input.len() <= 64,
        "input too long for 64-byte field: {} bytes",
        input.len()
    );
    let mut out = [0u8; 64];
    out[..input.len()].copy_from_slice(input);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_call_roundtrips_via_bincode() {
        let call = SolanaExternalCall {
            program_id: [7u8; 32],
            instruction_data: vec![1, 2, 3, 4, 5],
            expected_output: vec![1],
            output_mode: OutputMode::ReturnData,
            num_accounts: 12,
        };
        let bytes = call.encode();
        let back = SolanaExternalCall::decode(&bytes).expect("decode");
        assert_eq!(call, back);
    }

    #[test]
    fn wrap_input_length_is_186_bytes() {
        let bytes = encode_wrap_forwarder_input(
            &[1u8; 32],
            42,
            &[2u8; 32],
            7,
            1_700_000_000,
            &[3u8; 32],
            &[4u8; 64],
            2,
        );
        assert_eq!(bytes.len(), 186);
        assert_eq!(bytes[0], OP_WRAP);
    }

    #[test]
    fn unwrap_input_length_is_73_bytes() {
        let bytes = encode_unwrap_forwarder_input(&[1u8; 32], 100, &[2u8; 32]);
        assert_eq!(bytes.len(), 73);
        assert_eq!(bytes[0], OP_UNWRAP);
    }
}
