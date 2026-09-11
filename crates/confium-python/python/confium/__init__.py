"""Confium Python bindings.

Public API surface:

    >>> import confium
    >>> confium.version()
    '0.3.0'
    >>> confium.composite.ED25519
    'Ed25519'
    >>> tree = confium.transparency.MerkleTree()

See the README for usage examples and the `tests/` directory for
end-to-end integration tests.
"""
from __future__ import annotations

from .confium import (  # type: ignore[attr-defined]
    __version__,
    attributes,
    composite,
    core_version,
    deployment,
    ers,
    ots,
    pki,
    signatif,
    tc,
    transparency,
    version,
    xmldsig,
)
from .tc_share_file import ShareFile

__all__ = [
    "ShareFile",
    "__version__",
    "attributes",
    "composite",
    "core_version",
    "deployment",
    "errors",
    "ers",
    "ots",
    "pki",
    "signatif",
    "tc",
    "transparency",
    "version",
    "xmldsig",
]
