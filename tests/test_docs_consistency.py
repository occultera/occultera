# SPDX-License-Identifier: AGPL-3.0-only
"""Docs must not drift from the code: version labels, known-wrong claims and broken internal links."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIKI = ROOT / "docs" / "wiki"
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
MINOR = ".".join(VERSION.split(".")[:2])

# Claims that were once published and are wrong for this code. Keep the list short and specific.
BANNED = [
    r"per-client rate",                 # the MCP limit is per source IP (app/mcp.py client_ip)
    r"istemci başına hız",
    r"por cliente\.",
    r"débit par client",
    r"never reaches the AI",            # masking covers detected kinds only; IPs are kept by default
    r"does not reach the AI",
    r"yapay zekâya gitmez",
    r"hiç kişisel veri gitm",
    r"no personal data goes to the AI",
    r"off \(default\) \| mask",         # privacy.mode defaults to mask (app/config.py)
]


def _docs():
    yield from ROOT.glob("README*.md")
    yield from (ROOT / "docs").rglob("*.md")


def test_getting_started_is_labelled_for_this_minor_version():
    for name, pat in (("Getting-Started.md", rf"Applies to {re.escape(MINOR)}\.\d+"),
                      ("Getting-Started-TR.md", rf"{re.escape(MINOR)}\.\d+ için geçerlidir")):
        text = (WIKI / name).read_text(encoding="utf-8")
        assert re.search(pat, text), f"{name}: re-check the guide on {VERSION} and update its label"


def test_no_known_wrong_claims():
    bad = []
    for p in _docs():
        text = p.read_text(encoding="utf-8")
        for rx in BANNED:
            for m in re.finditer(rx, text, re.I):
                line = text.count("\n", 0, m.start()) + 1
                bad.append(f"{p.relative_to(ROOT)}:{line}: {m.group(0)}")
    assert not bad, "wrong claims in docs:\n" + "\n".join(bad)


def test_wiki_internal_links_resolve():
    pages = {p.stem for p in WIKI.glob("*.md")}
    missing = []
    for p in WIKI.glob("*.md"):
        if p.name == "README.md":       # how-to for the wiki sync, with placeholder links
            continue
        text = re.sub(r"```.*?```", "", p.read_text(encoding="utf-8"), flags=re.S)
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if re.match(r"(https?:|mailto:|#|\.\.?/|images/)", target) or "." in target.split("#")[0]:
                continue
            page = target.split("#")[0]
            if page and page not in pages:
                missing.append(f"{p.name} -> {target}")
    assert not missing, "broken wiki links:\n" + "\n".join(sorted(set(missing)))


def test_readme_relative_links_resolve():
    missing = []
    for p in ROOT.glob("README*.md"):
        for target in re.findall(r"\]\(([^)\s]+)\)", p.read_text(encoding="utf-8")):
            if re.match(r"(https?:|mailto:|#)", target):
                continue
            if not (ROOT / target.split("#")[0]).exists():
                missing.append(f"{p.name} -> {target}")
    assert not missing, "broken README links:\n" + "\n".join(missing)
