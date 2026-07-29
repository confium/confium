//! Threshold computing (TC) methods.
//!
//! Skeleton handlers pending per-connection handle management and the
//! TC session store.

use crate::pending_method;

pending_method!(tc_session_create, "tc_session_create", "requires per-connection handle management (pending)");
pending_method!(tc_session_round, "tc_session_round", "requires per-connection handle management (pending)");
pending_method!(tc_session_result, "tc_session_result", "requires per-connection handle management (pending)");
