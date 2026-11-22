"""Indexer health beyond the colour: heap, circuit breaker, shards per heap, unassigned shards (Rosca, Nov 2026)."""
from app.wazuh import indexer_health as IH

GB = 1024 ** 3


def _stats(p, heap_gb=1, tripped=0):
    return {"nodes": {"x": {"name": "wazuh-indexer-0", "jvm": {"mem": {"heap_used_percent": p, "heap_max_in_bytes": heap_gb * GB}},
                            "breakers": {"parent": {"limit_size_in_bytes": int(0.95 * heap_gb * GB), "tripped": tripped}}}}}


def test_rosca_case_heap_breaker_and_shards():
    rows = IH.nodes(_stats(97, 1, tripped=12), [{"node": "wazuh-indexer-0", "shards": "554"}])
    assert rows[0]["heap_max_gb"] == 1.0 and rows[0]["shards"] == 554
    codes = {f["code"]: f for f in IH.findings({"status": "red"}, rows, None)}
    assert codes["indexer_heap"]["severity"] == "critical"
    assert codes["indexer_breaker"]["n"] == 12
    assert codes["indexer_shards"]["m"] == 20 and codes["indexer_shards"]["s"] == 554


def test_healthy_node_has_no_findings():
    rows = IH.nodes(_stats(55, 4), [{"node": "wazuh-indexer-0", "shards": "60"}])
    assert IH.findings({"status": "green"}, rows, None) == []


def test_recovery_after_restart_is_info_not_critical():
    shards = IH.shard_summary(
        [{"index": f"wazuh-alerts-4.x-2026.06.{d}", "prirep": "p", "state": "UNASSIGNED", "unassigned.reason": "CLUSTER_RECOVERED"}
         for d in range(10, 20)]
        + [{"index": "wazuh-alerts-4.x-2026.06.23", "prirep": "p", "state": "INITIALIZING", "unassigned.reason": "CLUSTER_RECOVERED"}])
    f = IH.findings({"status": "red", "active_shards_percent_as_number": 89.9, "initializing_shards": 1}, [], shards)
    assert [x["code"] for x in f] == ["indexer_recovering"] and f[0]["severity"] == "info" and f[0]["p"] == 89.9


def test_stuck_primaries_and_failed_allocation_and_single_node_replicas():
    rows = [{"index": "a", "prirep": "p", "state": "UNASSIGNED", "unassigned.reason": "ALLOCATION_FAILED"},
            {"index": "b", "prirep": "r", "state": "UNASSIGNED", "unassigned.reason": "INDEX_CREATED"}]
    codes = [x["code"] for x in IH.findings({"status": "red", "number_of_data_nodes": 1}, [], IH.shard_summary(rows))]
    assert codes == ["indexer_primaries", "indexer_alloc_failed", "indexer_replicas"]


def test_every_finding_has_a_message_in_every_language():
    from app.i18n import t
    for lang in ("en", "tr", "es", "fr", "de"):
        for code, kw in [("indexer_heap", {"node": "n", "p": 97, "g": 1.0}), ("indexer_breaker", {"node": "n", "n": 3, "g": 1.0}),
                         ("indexer_shards", {"node": "n", "s": 554, "g": 1.0, "m": 20}),
                         ("indexer_recovering", {"i": 3, "u": 57, "p": 89.9}), ("indexer_primaries", {"n": 1, "r": "x 1", "x": "a"}),
                         ("indexer_alloc_failed", {"n": 1}), ("indexer_replicas", {"n": 2}), ("indexer_breaker_now", {})]:
            msg = t(lang, f"flag.{code}", **kw)
            assert msg and "{" not in msg, (lang, code)
