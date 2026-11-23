"""
ResponseGuard is a security boundary, not code to refactor.

This test pins its exact bytes. It fails on ANY change to response/guard.py,
including formatting. If a change is genuinely necessary, it needs an explicit
human security review; only after that review should PINNED_SHA256 be updated,
in the same change, with the reviewer named in the commit.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

GUARD = Path(__file__).resolve().parents[2] / "response" / "guard.py"
PINNED_SHA256 = "F91996F1D4651CAA42135D13ABA37B3173CFE367EFA9A0F360BB7A680F04A14F"


def test_response_guard_is_unchanged() -> None:
    actual = hashlib.sha256(GUARD.read_bytes()).hexdigest().upper()
    assert actual == PINNED_SHA256, (
        "response/guard.py changed. ResponseGuard is a security boundary: revert the change, "
        "or get an explicit human security review before updating PINNED_SHA256."
    )
