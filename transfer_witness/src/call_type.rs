//! Op-code constants and forwarder input encoders are owned by
//! `anoma-pa-solana-client`. Re-exported here so existing callers using
//! `transfer_witness::call_type::{OP_WRAP, OP_UNWRAP, encode_*}` keep working.

use serde::{Deserialize, Serialize};

pub use anoma_pa_solana_client::external_call::{
    OP_UNWRAP, OP_WRAP, encode_unwrap_forwarder_input, encode_wrap_forwarder_input,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Wrap,
    Unwrap,
}
