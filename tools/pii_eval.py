# SPDX-License-Identifier: AGPL-3.0-only
"""Print how the default privacy profile handles the Turkish-first test vectors.

    python -m tools.pii_eval          # markdown table for the Privacy wiki page
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.privacy import Masker  # noqa: E402
from tests.data.pii_vectors import VECTORS  # noqa: E402


def results():
    m = Masker()
    for cat, line, value, expected in VECTORS:
        out = m.mask(line)
        got = "kept" if value in out else "masked"
        yield cat, line, out, value, expected, got


def main() -> int:
    rows = list(results())
    print("| Category | Input | What the model sees | Result |")
    print("|---|---|---|---|")
    for cat, line, out, _value, expected, got in rows:
        verdict = {("masked", "masked"): "masked", ("kept", "kept"): "kept (correct)",
                   ("miss", "kept"): "**not detected** (known gap)"}.get((expected, got), f"UNEXPECTED: {got}")
        print(f"| {cat} | `{line}` | `{out}` | {verdict} |")
    pii = [r for r in rows if r[4] in ("masked", "miss")]
    caught = sum(1 for r in pii if r[5] == "masked")
    fp = sum(1 for r in rows if r[4] == "kept" and r[5] == "masked")
    print(f"\nPersonal data masked: {caught}/{len(pii)} · false positives: {fp}/{sum(1 for r in rows if r[4] == 'kept')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
