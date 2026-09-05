//! Privacy-preserving cryptographic primitives.
//!
//! # Audit status
//!
//! **Unaudited.** Several modules are research-grade sketches; the
//! experimental ones (`multi_sig`) compile only behind
//! `unaudited-experimental`. No external cryptographic review.
//!
//! # Example
//!
//! ```
//! use confium_privacy::privacy_and_dist_patterns::dp_query;
//!
//! // Apply differential privacy noise to a numeric value.
//! // ε = 0.5 gives moderate privacy; lower ε = more noise = more privacy.
//! let true_value = 1234.0;
//! let perturbed = dp_query(true_value, /* sensitivity */ 1.0, /* epsilon */ 0.5);
//! assert!(perturbed.is_finite());
//! ```

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
/// Experimental demonstration primitive — NOT AUDITED.
/// verify_aggregate checks only structural validity; it does not
/// bind the signature to the message (the message parameter is
/// ignored). Must never be used for real security.
#[cfg(feature = "unaudited-experimental")]
pub mod multi_sig;
pub mod oblivious_transfer;
pub mod privacy_and_dist_patterns;
pub mod proxy_reencryption;
pub mod secure_aggregation;
pub mod side_channel;
pub mod threshold_decryption;
pub mod vdf;
pub mod vrf;
