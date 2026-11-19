# SPDX-License-Identifier: AGPL-3.0-only
"""requirements.lock must cover requirements.txt, with a hash for every pin (the image installs it with --require-hashes)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _name(s: str) -> str:
    return re.split(r"[<>=!~;\[ ]", s.strip(), maxsplit=1)[0].lower().replace("_", "-")


def test_lock_covers_requirements_and_is_hashed():
    req = {_name(x) for x in (ROOT / "requirements.txt").read_text().splitlines() if x.strip() and not x.startswith("#")}
    lock = (ROOT / "requirements.lock").read_text()
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", lock, re.M)
    names = {n.lower().replace("_", "-") for n, _ in pins}
    assert req <= names, f"not in requirements.lock (run tools/update-lock.sh): {sorted(req - names)}"
    blocks = re.split(r"^(?=[A-Za-z0-9_.-]+==)", lock, flags=re.M)
    assert all("--hash=sha256:" in b for b in blocks if "==" in b), "a pin without --hash"


def test_dockerfile_installs_the_lock():
    df = (ROOT / "Dockerfile").read_text()
    assert "--require-hashes" in df and "requirements.lock" in df
