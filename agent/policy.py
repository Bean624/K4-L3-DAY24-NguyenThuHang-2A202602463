"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
PRINCIPALS_PATH = DATA_DIR / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if PRINCIPALS_PATH.exists():
        try:
            return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Rule TỐI THIỂU bắt buộc:
    # classification == "restricted" and egress_enabled is True -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: Data classification 'restricted' with egress enabled violates exfiltration policy."

    # 2. Kiểm tra thời hạn hết hạn (TTL / expires_at)
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > exp:
                return False, f"DENY: Context expired at {context.expires_at} (current time {now.isoformat()})."
        except Exception:
            return False, f"DENY: Invalid ISO-8601 expires_at timestamp: '{context.expires_at}'."

    # 3. Kiểm tra danh tính principal (On-Behalf-Of)
    if not context.principal_id:
        return False, "DENY: Missing principal identity."

    principals = _load_principals()
    if context.principal_id not in principals:
        return False, f"DENY: Unknown principal identity '{context.principal_id}'."

    principal = principals[context.principal_id]

    # 4. Kiểm tra mục đích yêu cầu (purpose)
    if context.request_purpose:
        allowed_purposes = principal.get("purposes", [])
        if context.request_purpose not in allowed_purposes:
            return False, (
                f"DENY: Purpose '{context.request_purpose}' is not authorized for principal "
                f"'{context.principal_id}'. Allowed: {allowed_purposes}."
            )

    # 5. Kiểm tra quyền tool (effective permissions)
    if not context.requested_tool:
        return False, "DENY: No requested_tool specified."

    allowed_tools = principal.get("allowed_tools", [])
    if context.requested_tool not in allowed_tools:
        return False, (
            f"DENY: Tool '{context.requested_tool}' is not in allowed_tools for principal "
            f"'{context.principal_id}'. Allowed: {allowed_tools}."
        )

    # Giao với agent_scopes
    if context.agent_scopes and context.requested_tool not in context.agent_scopes:
        return False, (
            f"DENY: Tool '{context.requested_tool}' is not within agent scopes: {context.agent_scopes}."
        )

    # Nếu delegation_depth > 0, giao tiếp với parent_scopes
    if context.delegation_depth > 0:
        if context.requested_tool not in context.parent_scopes:
            return False, (
                f"DENY: Tool '{context.requested_tool}' exceeds parent scopes during delegation "
                f"(depth={context.delegation_depth}): {context.parent_scopes}."
            )

    # Mọi điều kiện hợp lệ
    return True, f"ALLOW: Action '{context.requested_tool}' permitted for principal '{context.principal_id}'."
