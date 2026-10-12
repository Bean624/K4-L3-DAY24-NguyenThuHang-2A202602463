"""Unit test kiểm chứng Bonus: Delete cascade giữ ledger verify (3 điểm)."""
from __future__ import annotations

import json
from pathlib import Path

from agent import ledger
from agent.cascade import delete_customer_cascade


def test_delete_cascade_removes_data_and_preserves_ledger_integrity(tmp_path):
    # Chuẩn bị fixtures tạm thời
    customers_file = tmp_path / "customers.json"
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    ledger_file = tmp_path / "ledger.jsonl"

    initial_customers = [
        {
            "customer_id": "KH-000100",
            "name": "Nguyễn Văn Test",
            "cccd": "123456789012",
            "phone": "0912345678",
            "bank_account": "1122334455",
            "email": "test@example.vn",
            "related_tickets": [1001, 1002],
        },
        {
            "customer_id": "KH-000200",
            "name": "Trần Thị Khác",
            "cccd": "987654321098",
            "phone": "0987654321",
            "bank_account": "9988776655",
            "email": "khac@example.vn",
            "related_tickets": [2001],
        },
    ]
    customers_file.write_text(json.dumps(initial_customers, ensure_ascii=False), encoding="utf-8")

    # Tạo các ticket file tương ứng
    (corpus_dir / "ticket-1001.md").write_text("Nội dung ticket 1001", encoding="utf-8")
    (corpus_dir / "ticket-1002.md").write_text("Nội dung ticket 1002", encoding="utf-8")
    (corpus_dir / "ticket-2001.md").write_text("Nội dung ticket 2001", encoding="utf-8")

    # Giả lập lịch sử ledger trước khi xoá
    ledger.append({
        "ts": "2026-10-12T00:00:00Z",
        "agent_id": "lab24-agent",
        "run_id": "run-001",
        "tool": "search_docs",
        "args_hash": "a1b2c3d4",
        "classification": "internal",
        "decision": "allow",
        "reason": "Search query for support",
        "on_behalf_of": "support_l1",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }, ledger_file)

    ledger.append({
        "ts": "2026-10-12T00:01:00Z",
        "agent_id": "lab24-agent",
        "run_id": "run-001",
        "tool": "read_customer",
        "args_hash": "e5f6g7h8",
        "classification": "restricted",
        "decision": "allow",
        "reason": "Read customer KH-000100 for DPO",
        "on_behalf_of": "dpo",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }, ledger_file)

    assert ledger.verify(ledger_file) is True

    # 1. Thực hiện Delete Cascade cho KH-000100
    res = delete_customer_cascade(
        customer_id="KH-000100",
        customers_path=customers_file,
        corpus_dir=corpus_dir,
        ledger_path=ledger_file,
        operator_id="dpo",
    )
    assert res["status"] == "success"

    # Kiểm tra dữ liệu đã thực sự biến mất khỏi customers.json
    updated_customers = json.loads(customers_file.read_text(encoding="utf-8"))
    assert len(updated_customers) == 1
    assert all(c["customer_id"] != "KH-000100" for c in updated_customers)

    # Kiểm tra các ticket liên quan trong corpus đã bị xoá
    assert not (corpus_dir / "ticket-1001.md").exists()
    assert not (corpus_dir / "ticket-1002.md").exists()
    assert (corpus_dir / "ticket-2001.md").exists()  # Ticket của khách khác vẫn còn

    # 2. KIỂM TRA ĐIỀU KIỆN QUAN TRỌNG NHẤT: Ledger Verify VẪN PHẢI LÀ TRUE
    assert ledger.verify(ledger_file) is True, (
        "Chuỗi băm ledger phải toàn vẹn sau khi thực hiện delete cascade"
    )

    # 3. ĐỐI CHỨNG: Nếu ai đó cố tình xoá thô 1 dòng trong ledger (naive deletion):
    lines = ledger_file.read_text(encoding="utf-8").splitlines()
    tampered_lines = [lines[0], lines[2]]  # Cố tình xoá dòng số 1
    tampered_file = tmp_path / "tampered_ledger.jsonl"
    tampered_file.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")
    assert ledger.verify(tampered_file) is False, (
        "Xoá dòng thô làm đứt prev_hash phải bị verify phát hiện ngay lập tức"
    )
