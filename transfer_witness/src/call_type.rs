//! The forwarder call an ephemeral resource triggers. The op codes, input
//! encoders and segment account counts are owned by `anoma-pa-solana-client`,
//! so the circuit and the on-chain forwarder agree byte for byte.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Wrap,
    Unwrap,
    Migrate,
}
