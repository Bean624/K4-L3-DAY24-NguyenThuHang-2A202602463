"""OPA Adapter cho PEP — Port chính sách sang Open Policy Agent (OPA) / Rego."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
REGO_FILE = Path(__file__).resolve().parent / "policy.rego"
PRINCIPALS_PATH = BASE_DIR / "data" / "principals.json"


def _load_principals() -> dict[str, dict]:
    if PRINCIPALS_PATH.exists():
        try:
            return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def evaluate_opa(context: PolicyContext) -> tuple[bool, str]:
    """Đánh giá quyết định chính sách theo đặc tả Rego trong agent/policy.rego."""
    principals = _load_principals()

    input_data = {
        "data_classification": context.data_classification,
        "request_purpose": context.request_purpose,
        "agent_owner": context.agent_owner,
        "delegation_depth": context.delegation_depth,
        "egress_enabled": context.egress_enabled,
        "principal_id": context.principal_id,
        "requested_tool": context.requested_tool,
        "agent_scopes": list(context.agent_scopes),
        "parent_scopes": list(context.parent_scopes),
        "expires_at": context.expires_at,
    }

    deny_reasons: list[str] = []

    # 1. Rule tối thiểu
    if input_data["data_classification"] == "restricted" and input_data["egress_enabled"]:
        deny_reasons.append(
            "DENY: Data classification 'restricted' with egress enabled violates exfiltration policy."
        )

    # 2. TTL
    if input_data["expires_at"]:
        try:
            exp = datetime.fromisoformat(input_data["expires_at"].replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                deny_reasons.append(f"DENY: Context expired at {input_data['expires_at']}.")
        except Exception:
            deny_reasons.append(f"DENY: Invalid ISO-8601 timestamp: {input_data['expires_at']}.")

    # 3. Identity
    pid = input_data["principal_id"]
    if not pid:
        deny_reasons.append("DENY: Missing principal identity.")
    elif pid not in principals:
        deny_reasons.append(f"DENY: Unknown principal identity '{pid}'.")

    # 4. Purpose
    if pid and pid in principals and input_data["request_purpose"]:
        allowed_purposes = principals[pid].get("purposes", [])
        if input_data["request_purpose"] not in allowed_purposes:
            deny_reasons.append(
                f"DENY: Purpose '{input_data['request_purpose']}' is not authorized for principal '{pid}'."
            )

    # 5. Scopes & Tools
    tool = input_data["requested_tool"]
    if not tool:
        deny_reasons.append("DENY: No requested_tool specified.")
    elif pid and pid in principals:
        allowed_tools = principals[pid].get("allowed_tools", [])
        if tool not in allowed_tools:
            deny_reasons.append(f"DENY: Tool '{tool}' is not in allowed_tools for principal '{pid}'.")

    if tool and input_data["agent_scopes"] and tool not in input_data["agent_scopes"]:
        deny_reasons.append(f"DENY: Tool '{tool}' is not within agent scopes.")

    if tool and input_data["delegation_depth"] > 0:
        if tool not in input_data["parent_scopes"]:
            deny_reasons.append(f"DENY: Tool '{tool}' exceeds parent scopes during delegation.")

    # Kết quả đánh giá OPA
    if deny_reasons:
        return False, deny_reasons[0]

    return True, f"ALLOW: Action '{tool}' permitted for principal '{pid}' under OPA policy."
