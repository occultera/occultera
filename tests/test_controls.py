# SPDX-License-Identifier: AGPL-3.0-only
"""ISO 27001 Annex A evidence summary in the monthly audit report."""
import os

from app.audit import build, markdown
from app.config import load_settings
from app.config.models import ComplianceCfg
from app.controls import CATALOG, counts, digest, evaluate
from app.runtime import Runtime

ROOT = os.path.dirname(os.path.dirname(__file__))


def _st(d, cfg=None):
    return {c["id"]: c for c in evaluate(d, cfg or ComplianceCfg())}


def test_empty_report_is_all_no_data():
    r = _st({})
    assert set(r) == set(CATALOG) and {c["status"] for c in r.values()} == {"no_data"}


def test_outage_volume_and_sla():
    d = {"volume": {"total": 1000}, "liveness": {"events": [{"start": "x", "end": "y", "minutes": 214}] * 3, "minutes": 214},
         "vulnerabilities": {"severity": {"High": 4}, "sla": {"High": {"days": 30, "overdue": 0}}}}
    r = _st(d)
    assert r["A.8.15"]["status"] == "gap" and r["A.8.15"]["params"]["m"] == 214
    assert r["A.8.8"]["status"] == "evidence"


def test_exclusion_and_reference():
    cfg = ComplianceCfg(exclude={"A.5.9": "inventory kept in the CMDB"}, isms_refs={"A.8.16": "ISMS-23"})
    r = _st({}, cfg)
    assert r["A.5.9"]["status"] == "excluded" and r["A.5.9"]["params"]["r"] == "inventory kept in the CMDB"
    assert r["A.8.16"]["ref"] == "ISMS-23"


def test_findings_decisions_and_changes():
    d = {"findings": {"notable": [{"label": "real_incident", "user_status": "new", "note": ""},
                                  {"label": "detection_gap", "user_status": "accepted"}]},
         "rule_changes": [{"by": "", "action": "deploy"}, {"by": "rustem", "action": "deploy"}]}
    r = _st(d)
    assert r["A.5.25"]["status"] == "gap" and r["A.5.26"]["status"] == "gap" and r["A.8.32"]["params"]["u"] == 1


def test_digest_is_stable():
    d = {"a": 1, "b": [1, 2]}
    assert digest(d) == digest({"b": [1, 2], "a": 1, "controls": [1]})


async def test_audit_report_carries_the_summary():
    rt = Runtime(load_settings(os.path.join(ROOT, "config/demo.yaml")), demo=True)
    er = rt.get("demo")
    await rt.run_triage(er, "demo-c1")
    d = await build(rt, "demo")
    assert len(d["controls"]) == len(CATALOG) and len(d["sha256"]) == 64
    assert d["section_controls"]["vulnerabilities"] == ["A.8.8"]
    assert sum(counts(d["controls"]).values()) == len(CATALOG)
    md = markdown(d, "tr")
    assert "ISO 27001 Annex A" in md and "A.8.16" in md and "uygunluk beyanı değildir" in md
    from app.pdf import audit_pdf
    assert audit_pdf(d, "en")[:4] == b"%PDF"
