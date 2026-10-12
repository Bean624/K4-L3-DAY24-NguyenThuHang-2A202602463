"""Unit test kiểm chứng Bonus: Port policy sang OPA/Rego (4 điểm)."""
from __future__ import annotations

from pathlib import Path

from agent.policy import PolicyContext
from agent.policy_opa import evaluate_opa, REGO_FILE

FUTURE = "2099-01-01T00:00:00+00:00"
SCOPES = ("search_docs", "read_customer", "http_post")


def test_rego_policy_file_exists_and_valid():
    assert REGO_FILE.exists(), "File agent/policy.rego phải tồn tại"
    content = REGO_FILE.read_text(encoding="utf-8")
    assert "package agent.policy" in content
    assert "deny_reasons" in content
    assert "input.data_classification" in content


def test_opa_blocks_restricted_data_with_egress():
    ctx = PolicyContext(
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner="lab24-agent",
        delegation_depth=0,
        egress_enabled=True,
        principal_id="dpo",
        requested_tool="read_customer",
        agent_scopes=SCOPES,
        expires_at=FUTURE,
    )
    allow, reason = evaluate_opa(ctx)
    assert allow is False
    assert "restricted" in reason.lower() and "egress" in reason.lower()


def test_opa_enforces_obo_permissions():
    # support_l1 không được gọi read_customer
    ctx_support = PolicyContext(
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner="lab24-agent",
        delegation_depth=0,
        egress_enabled=False,
        principal_id="support_l1",
        requested_tool="read_customer",
        agent_scopes=SCOPES,
        expires_at=FUTURE,
    )
    allow_s, reason_s = evaluate_opa(ctx_support)
    assert allow_s is False
    assert "allowed_tools" in reason_s

    # dpo được gọi read_customer cho mục đích hợp lệ
    ctx_dpo = PolicyContext(
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner="lab24-agent",
        delegation_depth=0,
        egress_enabled=False,
        principal_id="dpo",
        requested_tool="read_customer",
        agent_scopes=SCOPES,
        expires_at=FUTURE,
    )
    allow_d, reason_d = evaluate_opa(ctx_dpo)
    assert allow_d is True
    assert "ALLOW" in reason_d
