//! Enterprise observability utilities: structured logging, trace correlation,
//! metric cardinality, RNG testing, zeroization audit, syslog forwarding.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0
#![allow(dead_code)] // sketch data structures expose pub fields for upcoming consumers

pub mod data_structures_and_utils;
pub mod observability_and_enterprise;
