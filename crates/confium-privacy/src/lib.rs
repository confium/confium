//! Privacy-preserving cryptographic primitives.

#![forbid(unsafe_code)]
#![allow(missing_docs)] // TODO: document before 1.0
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::invalid_html_tags)]

pub mod adaptor_sig;
pub mod blind_ecdsa;
pub mod differential;
pub mod distributed_prf;
pub mod distributed_prg;
pub mod jsonld_signing;
pub mod multi_sig;
pub mod oblivious_transfer;
pub mod privacy_and_dist_patterns;
pub mod proxy_reencryption;
pub mod secure_aggregation;
pub mod side_channel;
pub mod threshold_decryption;
pub mod vdf;
pub mod vrf;
