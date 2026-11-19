# SPDX-License-Identifier: AGPL-3.0-only
"""Load the demo's synthetic alerts and vulnerabilities into a real OpenSearch / Wazuh indexer (CI smoke test).

    python -m tools.smoke_seed http://127.0.0.1:9200

Installs Wazuh's own alerts template first (WAZUH_TEMPLATE_URL, the file from the Wazuh repository), so field
types are the ones a real Wazuh indexer has; then bulk-loads ~3k alerts over 18 days and the vulnerability states.
"""
import json
import os
import sys
from collections import defaultdict

import httpx

from app.demo import generate, generate_vulns

TEMPLATE = os.environ.get("WAZUH_TEMPLATE_URL",
                          "https://raw.githubusercontent.com/wazuh/wazuh/v4.14.1/extensions/elasticsearch/7.x/wazuh-template.json")


def bulk(c: httpx.Client, index_of, docs: list[dict]) -> int:
    by = defaultdict(list)
    for d in docs:
        by[index_of(d)].append(d)
    n = 0
    for idx, items in by.items():
        lines = []
        for d in items:
            lines += [json.dumps({"index": {"_index": idx}}), json.dumps(d)]
        r = c.post("/_bulk", content="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"})
        r.raise_for_status()
        if r.json().get("errors"):
            bad = next(i for i in r.json()["items"] if i["index"].get("error"))
            raise SystemExit(f"bulk error in {idx}: {bad['index']['error']}")
        n += len(items)
    return n


def main(url: str) -> None:
    with httpx.Client(base_url=url.rstrip("/"), timeout=60) as c:
        tpl = httpx.get(TEMPLATE, timeout=60, follow_redirects=True)
        tpl.raise_for_status()
        c.put("/_template/wazuh", json=tpl.json()).raise_for_status()
        alerts = generate()
        n = bulk(c, lambda d: "wazuh-alerts-4.x-" + d["timestamp"][:10].replace("-", "."), alerts)
        # The states index of a real Wazuh is created by the manager with keyword fields; mirror the ones the
        # application reads, so terms aggregations behave as in production.
        kw = {"type": "keyword"}
        c.put("/wazuh-states-vulnerabilities-smoke", json={"mappings": {"properties": {
            "agent": {"properties": {"id": kw, "name": kw}}, "package": {"properties": {"name": kw}},
            "vulnerability": {"properties": {"id": kw, "severity": kw,
                                             "detected_at": {"type": "date"}}}}}}).raise_for_status()
        v = bulk(c, lambda d: "wazuh-states-vulnerabilities-smoke", generate_vulns())
        c.post("/_refresh").raise_for_status()
        cnt = c.get("/wazuh-alerts-4.x-*/_count").json()["count"]
        print(f"loaded {n} alerts ({cnt} searchable) and {v} vulnerability states")
        assert cnt == n


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9200")
