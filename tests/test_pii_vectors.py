# SPDX-License-Identifier: AGPL-3.0-only
"""Regression guard for the published PII table: every vector must behave as documented."""
import pytest

from app.privacy import Masker
from tests.data.pii_vectors import VECTORS


@pytest.mark.parametrize("cat,line,value,expected", VECTORS, ids=[f"{v[0]}-{i}" for i, v in enumerate(VECTORS)])
def test_vector(cat, line, value, expected):
    out = Masker().mask(line)
    if expected == "masked":
        assert value not in out, f"{cat}: personal data leaked: {out}"
    else:   # "kept" (must not be touched) and "miss" (known gap, documented on the Privacy page)
        assert value in out, f"{cat}: behaviour changed, update the vectors and the Privacy page: {out}"
