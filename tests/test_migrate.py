# SPDX-License-Identifier: AGPL-3.0-only
"""occultera-migrate: 4.x XML → Sigma, review list, field map, match check."""
import json

import yaml

from app.migrate import convert
from app.migrate.__main__ import main
from app.migrate.check import check

XML = """
<group name="local,sshd,">
  <rule id="100100" level="10">
    <if_sid>5716</if_sid>
    <srcip>!10.0.0.0/8</srcip>
    <description>SSH failed login from outside</description>
    <mitre><id>T1110</id></mitre>
  </rule>
  <rule id="100101" level="5">
    <decoded_as>web-accesslog</decoded_as>
    <url>^/wp-login.php</url>
    <match>POST</match>
    <description>WordPress login attempt</description>
    <group>web,</group>
  </rule>
  <rule id="100102" level="12" frequency="8" timeframe="120">
    <if_matched_sid>100101</if_matched_sid>
    <same_source_ip />
    <description>WordPress brute force</description>
  </rule>
  <rule id="100103" level="7">
    <if_sid>100101</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\\.exe$</field>
    <description>child of 100101</description>
  </rule>
  <rule id="100104" level="3">
    <list field="srcip" lookup="address_match_key">etc/lists/bad-ips</list>
    <description>list only</description>
  </rule>
</group>
"""


def test_conversion_and_review_list():
    res = convert(XML)
    rows = {r["id"]: r for r in res["rules"]}
    s1 = rows["100100"]["sigma"]
    assert rows["100100"]["status"] == "review"                      # stock parent 5716
    assert s1["level"] == "high" and "attack.t1110" in s1["tags"]
    assert s1["detection"]["filter_1"] == {"source.ip|cidr": ["10.0.0.0/8"]}
    s2 = rows["100101"]["sigma"]
    assert rows["100101"]["status"] == "converted"
    assert s2["logsource"] == {"product": "wazuh", "service": "web-accesslog"}
    assert s2["detection"]["selection"]["event.original|contains"] == "POST"
    assert rows["100102"]["status"] == "review" and any("correlation" in x for x in rows["100102"]["review"])
    corr = rows["100102"]["correlation"]["correlation"]
    assert corr == {"type": "event_count", "rules": [rows["100102"]["sigma"]["id"]], "group-by": ["source.ip"],
                    "timespan": "120s", "condition": {"gte": 8}}
    assert len(list(yaml.safe_load_all(rows["100102"]["yaml"]))) == 2
    child = rows["100103"]
    assert "conditions of parent rule 100101 inlined" in child["notes"]
    assert child["sigma"]["detection"]["selection"]["data.win.eventdata.image|re"] == "(?i)powershell\\.exe$"
    assert rows["100104"]["status"] == "unsupported"
    assert res["summary"]["total"] == 5 and res["summary"]["coverage_percent"] == 40
    yaml.safe_load(rows["100101"]["yaml"])                           # valid YAML


def test_match_check_agrees_on_sample_events():
    events = [
        {"full_log": "1.2.3.4 - - POST /wp-login.php HTTP/1.1", "decoder": {"name": "web-accesslog"},
         "data": {"url": "/wp-login.php", "srcip": "1.2.3.4"}},
        {"full_log": "1.2.3.4 - - GET /wp-login.php HTTP/1.1", "decoder": {"name": "web-accesslog"},
         "data": {"url": "/wp-login.php", "srcip": "1.2.3.4"}},
        {"full_log": "POST /index.php", "decoder": {"name": "web-accesslog"}, "data": {"url": "/index.php"}},
    ]
    res = convert(XML)
    c = check(XML, res["rules"], events)
    assert c["100101"] == {"events": 3, "xml_matches": 1, "sigma_matches": 1, "agree": 3, "skipped": []}


def test_cli(tmp_path):
    x = tmp_path / "local_rules.xml"
    x.write_text(XML, encoding="utf-8")
    ev = tmp_path / "ev.jsonl"
    ev.write_text(json.dumps({"full_log": "POST x", "data": {"url": "/wp-login.php"}}) + "\n", encoding="utf-8")
    out = tmp_path / "out"
    assert main([str(x), "--events", str(ev), "--out", str(out), "--json"]) == 0
    assert (out / "wazuh-100101.yml").exists() and not (out / "wazuh-100104.yml").exists()
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "coverage 40 %" in md and "source.ip" in md
