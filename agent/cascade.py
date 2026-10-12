"""Module hỗ trợ Delete Cascade tuân thủ GDPR Art. 17 / Luật Dữ liệu 91/2025.

Bảo đảm nguyên tắc:
1. Xoá hồ sơ khách hàng khỏi kho dữ liệu nhạy cảm (data/customers.json).
2. Xoá/redact các ticket liên quan đến khách hàng trong corpus.
3. Ghi nhận sự kiện huỷ dữ liệu (Erasure Certificate / Tombstone) vào ledger
   mà KHÔNG làm đứt gãy chuỗi băm SHA-256 (tamper-evident hash chain).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger


def delete_customer_cascade(
    customer_id: str,
    customers_path: Path,
    corpus_dir: Path | None = None,
    ledger_path: Path | None = None,
    operator_id: str = "dpo",
) -> dict:
    customers_path = Path(customers_path)
    if not customers_path.exists():
        raise FileNotFoundError(f"Customers file not found: {customers_path}")

    customers = json.loads(customers_path.read_text(encoding="utf-8"))
    target = None
    remaining_customers = []

    for c in customers:
        if c.get("customer_id") == customer_id:
            target = c
        else:
            remaining_customers.append(c)

    if target is None:
        return {"status": "not_found", "customer_id": customer_id, "deleted_records": 0}

    # 1. Cập nhật lại kho dữ liệu customers.json (loại bỏ khách hàng)
    customers_path.write_text(
        json.dumps(remaining_customers, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # 2. Cascade xoá/vô hiệu hoá các ticket liên quan trong corpus nếu có
    deleted_tickets = []
    related_tickets = target.get("related_tickets", [])
    if corpus_dir is not None:
        corpus_path = Path(corpus_dir)
        for tid in related_tickets:
            for pattern in (f"ticket-{tid:03d}.md", f"ticket-{tid}.md"):
                tfile = corpus_path / pattern
                if tfile.exists():
                    tfile.unlink()
                    deleted_tickets.append(pattern)

    # 3. Ghi nhận Tombstone / Erasure Event vào Ledger bảo toàn chuỗi băm
    ledger_entry = None
    if ledger_path is not None:
        now = datetime.now(timezone.utc).isoformat()
        args_payload = {"customer_id": customer_id, "related_tickets": related_tickets}
        args_hash = hashlib.sha256(
            json.dumps(args_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:16]

        entry = {
            "ts": now,
            "agent_id": "lab24-agent/cascade-service",
            "run_id": f"cascade-{uuid.uuid4().hex[:8]}",
            "tool": "delete_customer_cascade",
            "args_hash": args_hash,
            "classification": "restricted",
            "decision": "allow",
            "reason": (
                f"ALLOW: GDPR Art. 17 / Luật Dữ liệu 91/2025 Right to Erasure cascade for "
                f"customer {customer_id} executed by operator {operator_id}."
            ),
            "on_behalf_of": operator_id,
            "expires_at": "2099-01-01T00:00:00+00:00",
        }
        ledger_entry = ledger.append(entry, Path(ledger_path))

    return {
        "status": "success",
        "customer_id": customer_id,
        "deleted_tickets": deleted_tickets,
        "ledger_entry": ledger_entry,
    }
