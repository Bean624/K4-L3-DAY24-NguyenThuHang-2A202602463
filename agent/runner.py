"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _hash_args(args: dict) -> str:
    raw = json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _load_customers() -> list[dict]:
    if CUSTOMERS_FILE.exists():
        try:
            return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def _get_purposes(principal_id: str) -> list[str]:
    if PRINCIPALS_FILE.exists():
        try:
            data = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
            return data.get(principal_id, {}).get("purposes", [])
        except Exception:
            pass
    return []


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH

    now = datetime.now(timezone.utc)
    ts = now.isoformat()
    expires_at = (now + timedelta(hours=1)).isoformat()
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    purposes = _get_purposes(principal_id)
    purpose_read = "support-reply" if "support-reply" in purposes else (purposes[0] if purposes else "support-reply")
    purpose_search = "summarize-tickets" if "summarize-tickets" in purposes else (purposes[0] if purposes else "summarize-tickets")

    # -------------------------------------------------------------
    # RUN A: Untrusted Content (search_docs)
    # -------------------------------------------------------------
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose=purpose_search,
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)

    ledger.append(
        {
            "ts": ts,
            "agent_id": "lab24-agent/run-a",
            "run_id": run_id,
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách."

    docs = tools.search_docs(message)

    # -------------------------------------------------------------
    # Trifecta Split: Sanitize & Trích xuất ticket_id từ TÊN FILE
    # -------------------------------------------------------------
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d.get("id", ""))
        if m:
            ticket_ids.append(int(m.group(1)))

    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # -------------------------------------------------------------
    # RUN B: Private Data Store (read_customer)
    # -------------------------------------------------------------
    customers = _load_customers()
    matched_customer_ids: list[str] = []
    for c in customers:
        cid = c.get("customer_id")
        rel = c.get("related_tickets", [])
        if any(tid in rel for tid in ticket_ids):
            if cid and cid not in matched_customer_ids:
                matched_customer_ids.append(cid)

    collected_records = []
    for customer_id in matched_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose=purpose_read,
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)

        ledger.append(
            {
                "ts": ts,
                "agent_id": "lab24-agent/run-b",
                "run_id": run_id,
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": customer_id}),
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_read:
            try:
                rec = tools.read_customer(customer_id)
                collected_records.append(rec)
            except tools.ToolError:
                pass

    # -------------------------------------------------------------
    # Egress Containment: Chặn khi có injection đòi POST ra ngoài
    # -------------------------------------------------------------
    if injected is not None:
        target_url = getattr(injected, "target_url", "http://127.0.0.1:10024/reconcile")
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose=purpose_read,
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)

        ledger.append(
            {
                "ts": ts,
                "agent_id": "lab24-agent/run-b",
                "run_id": run_id,
                "tool": "http_post",
                "args_hash": _hash_args({"url": target_url}),
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_post:
            try:
                tools.http_post(target_url, {"records": collected_records})
            except Exception:
                pass

    return llm.summarize(docs)
