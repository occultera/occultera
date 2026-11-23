# SPDX-License-Identifier: AGPL-3.0-only
"""The AI and MCP clients name fields with their 4.x names; the adapter translates them per environment."""
import pytest

from app import query_guard as Q
from app.wazuh import schema as W

V5ISH = W.Schema(version=97, alerts_index="wazuh-findings-v5-*", vuln_index="wazuh-states-vulnerabilities-*",
                 RULE_LEVEL="wazuh.rule.level", AGENT_NAME="wazuh.agent.name", SRCIP="source.ip",
                 RULE_ID="wazuh.rule.id")


def test_identity_on_4x():
    assert Q.field("rule.level") == "rule.level"
    assert Q.query_string('agent.name:web01 AND data.srcip:"10.0.0.1"') == 'agent.name:web01 AND data.srcip:"10.0.0.1"'


def test_translated_on_another_schema():
    with W.using(V5ISH):
        assert Q.field("rule.level") == "wazuh.rule.level"
        assert Q.field("wazuh.agent.name") == "wazuh.agent.name"        # a physical name of this schema is accepted
        q = Q.query_string('agent.name:web01 AND (rule.id:5710 OR data.srcip:"rule.id:x") AND sshd')
        assert q == 'wazuh.agent.name:web01 AND (wazuh.rule.id:5710 OR source.ip:"rule.id:x") AND sshd'
        with pytest.raises(Q.QueryError):
            Q.field("wazuh.secret.field")


def test_extra_fields_pass_unchanged():
    with W.using(V5ISH):
        assert Q.field("data.win.eventdata.image", ["data.win.*"]) == "data.win.eventdata.image"
