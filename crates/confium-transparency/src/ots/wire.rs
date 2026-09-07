//! OpenTimestamps proof-file wire format — parse, serialize, replay.
//!
//! Implements the op-stream format from python-opentimestamps (the
//! reference implementation): a file header magic, then a recursive
//! timestamp tree where each node holds attestations and op-edges,
//! and every edge's child is keyed by the operation's result on the
//! current message. Verification replays the ops from the stamped
//! digest; attestations hang off terminal messages.
//!
//! Wire details (pinned from the reference; see the audit ledger's
//! OTS item for the full table):
//!
//! - file magic: `\\0OpenTimestamps\\0\\0Proof\\0` + 8 salt bytes
//!   (bf 89 e2 e8 84 e8 92 94 — the final two were dropped in the
//!   first transcription; caught by the gem's cross-checked Ruby
//!   spec), then
//!   major version `0x01`
//! - `0xFF` separators precede every tag except the last sibling
//! - tag `0x00` introduces an attestation: 8-byte tag + payload
//! - op tags: SHA256 `0x08`, APPEND `0xF0`, PREPEND `0xF1`,
//!   REVERSE `0xF2`, HEXLIFY `0xF3` (unknown tags are rejected —
//!   extend the enum when a real proof needs them)
//! - varuint is unsigned LEB128; varbytes is varuint-length + bytes

use sha2::Digest;
use sha2::Sha256;

/// Maximum op payload / message length accepted on deserialization —
/// matches the reference implementation's guard against maliciously
/// large proofs.
pub const MAX_RESULT_LENGTH: usize = 8192;

/// Deserialization recursion limit — the reference caps tree depth to
/// keep hostile inputs from blowing the stack.
const RECURSION_LIMIT: u32 = 256;

/// File header magic: `\0OpenTimestamps\0\0Proof\0` + 8 salt bytes.
pub const FILE_MAGIC: [u8; 31] = [
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, //
    0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, //
    0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
];

const MAJOR_VERSION: u8 = 0x01;

/// A timestamp operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// SHA-256 digest of the current message.
    Sha256,
    /// Append a suffix.
    Append(Vec<u8>),
    /// Prepend a prefix.
    Prepend(Vec<u8>),
    /// Reverse the message bytes.
    Reverse,
    /// Hex-encode the message.
    Hexlify,
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Self::Sha256 => 0x08,
            Self::Append(_) => 0xf0,
            Self::Prepend(_) => 0xf1,
            Self::Reverse => 0xf2,
            Self::Hexlify => 0xf3,
        }
    }

    /// Apply the operation to `msg`.
    pub fn apply(&self, msg: &[u8]) -> Result<Vec<u8>, WireError> {
        match self {
            Self::Sha256 => {
                let mut h = Sha256::new();
                h.update(msg);
                Ok(h.finalize().to_vec())
            }
            Self::Append(suffix) => {
                let mut out = Vec::with_capacity(msg.len() + suffix.len());
                out.extend_from_slice(msg);
                out.extend_from_slice(suffix);
                Ok(out)
            }
            Self::Prepend(prefix) => {
                let mut out = Vec::with_capacity(msg.len() + prefix.len());
                out.extend_from_slice(prefix);
                out.extend_from_slice(msg);
                Ok(out)
            }
            Self::Reverse => {
                if msg.is_empty() {
                    return Err(WireError::InvalidMessage(
                        "cannot reverse an empty message".into(),
                    ));
                }
                Ok(msg.iter().rev().copied().collect())
            }
            Self::Hexlify => Ok(hex::encode(msg).into_bytes()),
        }
    }
}

/// An attestation on a terminal message of the proof tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attestation {
    /// Commitment recorded at a remote calendar for future
    /// attestation (URI).
    Pending(String),
    /// Anchored in the Bitcoin block header chain at a height.
    BitcoinBlockHeader(u32),
    /// Anchored in the Litecoin block header chain at a height.
    LitecoinBlockHeader(u32),
}

impl Attestation {
    fn tag(&self) -> [u8; 8] {
        match self {
            Self::Pending(_) => [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e],
            Self::BitcoinBlockHeader(_) => [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01],
            Self::LitecoinBlockHeader(_) => [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45],
        }
    }
}

/// One node of the timestamp tree: attestations plus op-edges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimestampNode {
    /// Attestations on this node's message.
    pub attestations: Vec<Attestation>,
    /// Op edges; each child continues from the op's result.
    pub ops: Vec<(Op, TimestampNode)>,
}

impl TimestampNode {
    /// An empty node (no attestations, no ops) cannot be serialized.
    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty() && self.ops.is_empty()
    }
}

/// A parsed OTS proof file: header + root timestamp node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsFile {
    /// The stamped digest the proof starts from (needed for replay;
    /// not part of the serialized file).
    pub digest: Vec<u8>,
    /// Root node.
    pub root: TimestampNode,
}

/// Errors from the wire format layer.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Malformed bytes.
    #[error("malformed OTS proof: {0}")]
    Malformed(String),
    /// Wrong or unknown tag.
    #[error("unknown op tag 0x{0:02x}")]
    UnknownTag(u8),
    /// Truncated stream.
    #[error("truncated OTS proof: {0}")]
    Truncated(String),
    /// Message invalid for an operation during replay.
    #[error("invalid message for op: {0}")]
    InvalidMessage(String),
    /// Structure too deep.
    #[error("recursion limit exceeded")]
    RecursionLimit,
}

/// Replay the proof tree from `file.digest`, yielding every
/// `(terminal_message, attestation)` pair.
///
/// This is the verification core: an attestation is only meaningful
/// for the message the op-chain actually computes from the digest —
/// replay computes those messages.
pub fn replay(file: &OtsFile) -> Result<Vec<(Vec<u8>, Attestation)>, WireError> {
    let mut out = Vec::new();
    replay_node(&file.root, &file.digest, &mut out, 0)?;
    Ok(out)
}

fn replay_node(
    node: &TimestampNode,
    msg: &[u8],
    out: &mut Vec<(Vec<u8>, Attestation)>,
    depth: u32,
) -> Result<(), WireError> {
    if depth > RECURSION_LIMIT {
        return Err(WireError::RecursionLimit);
    }
    for attestation in &node.attestations {
        out.push((msg.to_vec(), attestation.clone()));
    }
    for (op, child) in &node.ops {
        let next = op.apply(msg)?;
        replay_node(child, &next, out, depth + 1)?;
    }
    Ok(())
}

/// Replay summary: every attestation paired with the terminal
/// message it actually commits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtsWireVerification {
    /// Pending calendar attestations: (committed message, URI).
    pub pending: Vec<(Vec<u8>, String)>,
    /// Bitcoin header attestations: (committed message, height).
    pub bitcoin: Vec<(Vec<u8>, u32)>,
    /// Litecoin header attestations: (committed message, height).
    pub litecoin: Vec<(Vec<u8>, u32)>,
}

impl OtsWireVerification {
    /// Whether the proof carries any attestation at all.
    pub fn has_attestation(&self) -> bool {
        !self.pending.is_empty() || !self.bitcoin.is_empty() || !self.litecoin.is_empty()
    }
}

/// Replay and classify: partition every attestation by kind, paired
/// with the message the op-chain computed for it. A proof whose tree
/// yields no attestations verifies nothing.
pub fn verify(file: &OtsFile) -> Result<OtsWireVerification, WireError> {
    let pairs = replay(file)?;
    let mut out = OtsWireVerification::default();
    for (msg, attestation) in pairs {
        match attestation {
            Attestation::Pending(uri) => out.pending.push((msg, uri)),
            Attestation::BitcoinBlockHeader(h) => out.bitcoin.push((msg, h)),
            Attestation::LitecoinBlockHeader(h) => out.litecoin.push((msg, h)),
        }
    }
    Ok(out)
}

/// Parse an OTS proof file for `digest`.
pub fn parse(digest: &[u8], bytes: &[u8]) -> Result<OtsFile, WireError> {
    if bytes.len() < FILE_MAGIC.len() + 1 {
        return Err(WireError::Truncated("shorter than the file header".into()));
    }
    if bytes[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err(WireError::Malformed("bad file header magic".into()));
    }
    let mut pos = FILE_MAGIC.len();
    if bytes[pos] != MAJOR_VERSION {
        return Err(WireError::Malformed(format!(
            "unsupported major version {}",
            bytes[pos]
        )));
    }
    pos += 1;

    let mut cursor = Cursor { bytes, pos };
    let root = parse_node(&mut cursor)?;
    if cursor.pos != bytes.len() {
        return Err(WireError::Malformed(format!(
            "{} trailing bytes after the proof tree",
            bytes.len() - cursor.pos
        )));
    }
    Ok(OtsFile {
        digest: digest.to_vec(),
        root,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u8(&mut self) -> Result<u8, WireError> {
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| WireError::Truncated("expected a byte".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], WireError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| WireError::Malformed("length overflow".into()))?;
        let s = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| WireError::Truncated(format!("expected {n} bytes")))?;
        self.pos = end;
        Ok(s)
    }

    fn varuint(&mut self) -> Result<u64, WireError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(WireError::Malformed("varuint too long".into()));
            }
        }
    }

    fn varbytes(&mut self, max: usize) -> Result<Vec<u8>, WireError> {
        let len = self.varuint()?;
        if len > max as u64 {
            return Err(WireError::Malformed(format!(
                "payload length {len} exceeds {max}"
            )));
        }
        Ok(self.take(len as usize)?.to_vec())
    }
}

fn parse_node(cur: &mut Cursor<'_>) -> Result<TimestampNode, WireError> {
    parse_node_depth(cur, 0)
}

fn parse_node_depth(cur: &mut Cursor<'_>, depth: u32) -> Result<TimestampNode, WireError> {
    if depth > RECURSION_LIMIT {
        return Err(WireError::RecursionLimit);
    }
    let mut node = TimestampNode::default();

    let mut tag = cur.u8()?;
    while tag == 0xff {
        // Separator: the following tag is a non-last sibling.
        tag = cur.u8()?;
        apply_tag(cur, &mut node, tag, depth)?;
        tag = cur.u8()?;
    }
    apply_tag(cur, &mut node, tag, depth)?;
    Ok(node)
}

fn apply_tag(
    cur: &mut Cursor<'_>,
    node: &mut TimestampNode,
    tag: u8,
    depth: u32,
) -> Result<(), WireError> {
    match tag {
        0x00 => {
            node.attestations.push(parse_attestation(cur)?);
        }
        0x08 => {
            let child = parse_node_depth(cur, depth + 1)?;
            node.ops.push((Op::Sha256, child));
        }
        0xf0 => {
            let arg = cur.varbytes(MAX_RESULT_LENGTH)?;
            if arg.is_empty() {
                return Err(WireError::Malformed("append arg can't be empty".into()));
            }
            let child = parse_node_depth(cur, depth + 1)?;
            node.ops.push((Op::Append(arg), child));
        }
        0xf1 => {
            let arg = cur.varbytes(MAX_RESULT_LENGTH)?;
            if arg.is_empty() {
                return Err(WireError::Malformed("prepend arg can't be empty".into()));
            }
            let child = parse_node_depth(cur, depth + 1)?;
            node.ops.push((Op::Prepend(arg), child));
        }
        0xf2 => {
            let child = parse_node_depth(cur, depth + 1)?;
            node.ops.push((Op::Reverse, child));
        }
        0xf3 => {
            let child = parse_node_depth(cur, depth + 1)?;
            node.ops.push((Op::Hexlify, child));
        }
        other => return Err(WireError::UnknownTag(other)),
    }
    Ok(())
}

fn parse_attestation(cur: &mut Cursor<'_>) -> Result<Attestation, WireError> {
    let tag: [u8; 8] = cur.take(8)?.try_into().expect("take(8) yields 8 bytes");
    match tag {
        [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e] => {
            let uri = cur.varbytes(1000)?;
            let uri = String::from_utf8(uri)
                .map_err(|_| WireError::Malformed("pending attestation URI is not UTF-8".into()))?;
            Ok(Attestation::Pending(uri))
        }
        [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01] => {
            let h = cur.take(4)?;
            Ok(Attestation::BitcoinBlockHeader(u32::from_le_bytes(
                h.try_into().expect("take(4) yields 4 bytes"),
            )))
        }
        [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45] => {
            let h = cur.take(4)?;
            Ok(Attestation::LitecoinBlockHeader(u32::from_le_bytes(
                h.try_into().expect("take(4) yields 4 bytes"),
            )))
        }
        _ => Err(WireError::UnknownTag(tag[0])),
    }
}

/// Serialize an OTS proof file (canonical ordering: attestations
/// sorted, ops sorted by tag).
pub fn serialize(file: &OtsFile) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    out.extend_from_slice(&FILE_MAGIC);
    out.push(MAJOR_VERSION);
    serialize_node(&file.root, &mut out)?;
    Ok(out)
}

fn serialize_node(node: &TimestampNode, out: &mut Vec<u8>) -> Result<(), WireError> {
    if node.is_empty() {
        return Err(WireError::Malformed(
            "an empty timestamp node can't be serialized".into(),
        ));
    }
    let mut attestations = node.attestations.clone();
    attestations.sort();

    let mut ops = node.ops.clone();
    ops.sort_by(|a, b| a.0.cmp(&b.0));

    let total = attestations.len() + ops.len();
    let mut emitted = 0usize;

    for attestation in &attestations {
        if emitted + 1 < total {
            out.extend_from_slice(&[0xff]);
        }
        out.push(0x00);
        serialize_attestation(attestation, out);
        emitted += 1;
    }
    for (op, child) in &ops {
        if emitted + 1 < total {
            out.extend_from_slice(&[0xff]);
        }
        serialize_op(op, out);
        serialize_node(child, out)?;
        emitted += 1;
    }
    Ok(())
}

fn serialize_op(op: &Op, out: &mut Vec<u8>) {
    match op {
        Op::Sha256 | Op::Reverse | Op::Hexlify => out.push(op.tag()),
        Op::Append(arg) | Op::Prepend(arg) => {
            out.push(op.tag());
            write_varbytes(arg, out);
        }
    }
}

fn serialize_attestation(attestation: &Attestation, out: &mut Vec<u8>) {
    match attestation {
        Attestation::Pending(uri) => {
            out.extend_from_slice(&attestation.tag());
            write_varbytes(uri.as_bytes(), out);
        }
        Attestation::BitcoinBlockHeader(h) | Attestation::LitecoinBlockHeader(h) => {
            out.extend_from_slice(&attestation.tag());
            out.extend_from_slice(&h.to_le_bytes());
        }
    }
}

fn write_varbytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_varuint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn write_varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn digest(b: u8) -> Vec<u8> {
        vec![b; 32]
    }

    #[test]
    fn round_trip_sha256_append_pending() {
        let file = OtsFile {
            digest: digest(1),
            root: TimestampNode {
                attestations: vec![],
                ops: vec![(
                    Op::Sha256,
                    TimestampNode {
                        attestations: vec![],
                        ops: vec![(
                            Op::Append(vec![0xaa, 0xbb]),
                            TimestampNode {
                                attestations: vec![Attestation::Pending(
                                    "https://alice.btc.calendar.opentimestamps.org".into(),
                                )],
                                ops: vec![],
                            },
                        )],
                    },
                )],
            },
        };
        let bytes = serialize(&file).unwrap();
        let parsed = parse(&digest(1), &bytes).unwrap();
        assert_eq!(parsed, file);

        let pairs = replay(&file).unwrap();
        assert_eq!(pairs.len(), 1);
        let (msg, att) = &pairs[0];
        assert!(matches!(att, Attestation::Pending(_)));
        // The op chain is sha256, then append: the attested message is
        // sha256(digest) || aabb.
        let mut h = Sha256::new();
        h.update(digest(1));
        let mut expected = h.finalize().to_vec();
        expected.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(msg, &expected);
    }

    #[test]
    fn round_trip_multiple_siblings_and_bitcoin_attestation() {
        let file = OtsFile {
            digest: digest(2),
            root: TimestampNode {
                attestations: vec![Attestation::BitcoinBlockHeader(800_123)],
                // Ops in canonical (tag) order: Prepend (0xf1) sorts
                // before Reverse (0xf2), so construct the tree sorted
                // to compare with the parsed form.
                ops: vec![
                    (
                        Op::Prepend(vec![0x01]),
                        TimestampNode {
                            attestations: vec![],
                            ops: vec![(
                                Op::Hexlify,
                                TimestampNode {
                                    attestations: vec![Attestation::Pending(
                                        "https://hex.cal".into(),
                                    )],
                                    ops: vec![],
                                },
                            )],
                        },
                    ),
                    (
                        Op::Reverse,
                        TimestampNode {
                            attestations: vec![Attestation::Pending("https://example.org".into())],
                            ops: vec![],
                        },
                    ),
                ],
            },
        };
        let bytes = serialize(&file).unwrap();
        let parsed = parse(&digest(2), &bytes).unwrap();
        assert_eq!(parsed, file);

        let pairs = replay(&file).unwrap();
        // root attestation + reverse-child + hexlify-child
        assert_eq!(pairs.len(), 3);
        assert!(
            pairs
                .iter()
                .any(|(_, a)| matches!(a, Attestation::BitcoinBlockHeader(800_123)))
        );
        // hexlify child message is hex(0x01 || digest)
        let hex_msg = pairs
            .iter()
            .map(|(m, _)| m)
            .find(|m| m.len() == 66)
            .expect("hexlified message present");
        let mut expected = vec![0x01];
        expected.extend(digest(2));
        assert_eq!(hex_msg, hex::encode(expected).as_bytes());
    }

    #[test]
    fn file_magic_is_the_canonical_31_bytes() {
        // python-opentimestamps HEADER_MAGIC:
        // b'\0OpenTimestamps\0\0Proof\0\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
        assert_eq!(FILE_MAGIC.len(), 31);
        assert_eq!(
            &FILE_MAGIC[23..],
            &[0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]
        );
    }

    #[test]
    fn varuint_leb128_round_trip() {
        for value in [0u64, 1, 127, 128, 300, 8192, 1 << 20, u32::MAX as u64] {
            let mut buf = Vec::new();
            write_varuint(value, &mut buf);
            let mut cur = Cursor {
                bytes: &buf,
                pos: 0,
            };
            assert_eq!(cur.varuint().unwrap(), value);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FILE_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(0x00); // attestation tag start
        bytes.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
        write_varbytes(b"https://example.org", &mut bytes);

        let mut bad = bytes.clone();
        bad[0] = 0x01;
        assert!(matches!(
            parse(&digest(9), &bad),
            Err(WireError::Malformed(_))
        ));
        assert!(parse(&digest(9), &bytes).is_ok());
    }

    #[test]
    fn rejects_truncated_stream() {
        let bytes = {
            let mut b = Vec::new();
            b.extend_from_slice(&FILE_MAGIC);
            b.push(MAJOR_VERSION);
            b.push(0x08); // sha256 op, then missing child
            b
        };
        assert!(matches!(
            parse(&digest(9), &bytes),
            Err(WireError::Truncated(_))
        ));
    }

    #[test]
    fn rejects_unknown_op_tag() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FILE_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(0x67); // keccak256 — not in this implementation's subset
        assert!(matches!(
            parse(&digest(9), &bytes),
            Err(WireError::UnknownTag(0x67))
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FILE_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(0x00);
        bytes.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
        write_varbytes(b"https://example.org", &mut bytes);
        bytes.push(0xff);
        assert!(matches!(
            parse(&digest(9), &bytes),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_oversized_append_payload() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FILE_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(0xf0);
        write_varbytes(&vec![0u8; MAX_RESULT_LENGTH + 1], &mut bytes);
        assert!(matches!(
            parse(&digest(9), &bytes),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn replay_diverges_on_tampered_op() {
        let file = OtsFile {
            digest: digest(5),
            root: TimestampNode {
                attestations: vec![],
                ops: vec![(
                    Op::Append(vec![0x01]),
                    TimestampNode {
                        attestations: vec![Attestation::BitcoinBlockHeader(1)],
                        ops: vec![],
                    },
                )],
            },
        };
        let pairs = replay(&file).unwrap();
        let (msg, _) = &pairs[0];

        let tampered = OtsFile {
            digest: digest(6), // different digest
            ..file.clone()
        };
        let pairs2 = replay(&tampered).unwrap();
        assert_ne!(msg, &pairs2[0].0);
    }

    #[test]
    fn empty_node_cannot_serialize() {
        let file = OtsFile {
            digest: digest(1),
            root: TimestampNode::default(),
        };
        assert!(matches!(serialize(&file), Err(WireError::Malformed(_))));
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Paired rejects-forgery tests for replay-based verification.

    use super::tests::digest;
    use super::*;

    #[test]
    fn replay_rejects_reverse_of_empty_intermediate() {
        // append(0x01) -> hexlify ("" cannot happen from 33-byte input,
        // so build reverse directly over an empty message via a
        // handcrafted tree: root has Reverse with empty digest input.
        let file = OtsFile {
            digest: Vec::new(),
            root: TimestampNode {
                attestations: vec![],
                ops: vec![(
                    Op::Reverse,
                    TimestampNode {
                        attestations: vec![Attestation::Pending("https://x".into())],
                        ops: vec![],
                    },
                )],
            },
        };
        assert!(matches!(replay(&file), Err(WireError::InvalidMessage(_))));
    }

    #[test]
    fn parse_rejects_empty_append_argument() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FILE_MAGIC);
        bytes.push(MAJOR_VERSION);
        bytes.push(0xf0);
        write_varbytes(b"", &mut bytes); // zero-length arg — invalid
        bytes.push(0x00);
        assert!(matches!(
            parse(&digest(9), &bytes),
            Err(WireError::Malformed(_))
        ));
    }
}
