//! Op-code constants and forwarder input encoders live in the local
//! [`crate::external_call`] module. Re-exported here so existing callers using
//! `transfer_witness::call_type::{OP_WRAP, OP_UNWRAP, encode_*}` keep working.

use serde::{Deserialize, Serialize};

pub use crate::external_call::{
    OP_UNWRAP, OP_WRAP, encode_unwrap_forwarder_input, encode_wrap_forwarder_input,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    Wrap,
    Unwrap,
}
