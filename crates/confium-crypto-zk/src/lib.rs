//! Zero-knowledge proof systems and set-membership primitives.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0

pub mod accumulator;
pub mod threshold_abs;
pub mod zk_set_membership;
pub mod zk_sig_possession;
