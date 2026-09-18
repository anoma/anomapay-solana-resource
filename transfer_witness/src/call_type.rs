//! The forwarder call an ephemeral resource triggers. The op codes, the
//! input encoders and the size of the account segment the settlement
//! transaction carries for each call are owned by `anoma-pa-solana-client`,
//! so the circuit and the on-chain forwarder agree byte for byte.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Wrap,
    Unwrap,
}
