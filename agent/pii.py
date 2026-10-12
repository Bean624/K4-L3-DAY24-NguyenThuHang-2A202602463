"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Bước 3a.1 — Định nghĩa regex cho từng loại PII
# ---------------------------------------------------------------------------
# Giải thích chiến lược:
#
# 1. VN_CCCD = đúng 12 chữ số (\b đảm bảo không dính vào số dài hơn)
#    Ưu tiên cao nhất vì CCCD luôn đúng 12 số.
#
# 2. VN_PHONE = bắt đầu bằng 0, theo sau là 9 chữ số (tổng 10 số)
#    \b ở đầu và cuối để không nhầm với số dài hơn.
#    Cho phép dấu cách/gạch ngang sau mỗi nhóm (vd: 0912 345 678).
#
# 3. VN_BANK_ACCOUNT = 8-16 chữ số đứng gần keyword "STK"/"số tài khoản"
#    Dùng context window: tìm keyword trước, rồi lấy số đứng sau.
#    Mục đích: tránh nhầm CCCD (12 số) thành STK.
#
# 4. EMAIL = regex email chuẩn: local@domain.tld

# CCCD: đúng 12 chữ số, không nằm trong dãy số dài hơn
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

# Phone: bắt đầu 0, theo sau 9 chữ số (10 số tổng)
# Có thể có dấu cách/gạch ngang giữa các nhóm: 0912-345-678 hay 0912 345 678
_PHONE_RE = re.compile(r"(?<!\d)0\d{9}(?!\d)")

# STK: keyword "STK" hoặc "số tài khoản" (không phân biệt hoa thường),
# theo sau là khoảng trắng tùy chọn, rồi 8-16 chữ số
# Dùng lookahead để capture đúng vị trí số (không capture keyword)
_BANK_KEYWORD_RE = re.compile(
    r"(?:STK|số tài khoản|so tai khoan)\s*(\d{8,16})(?!\d)",
    re.IGNORECASE
)

# Email: local@domain.tld (hỗ trợ dấu chấm, gạch dưới, số trong local/domain)
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)


# ---------------------------------------------------------------------------
# Bước 3a.2 — Hàm detect()
# ---------------------------------------------------------------------------
def detect(text: str) -> list[dict]:
    """Phát hiện PII trong text, trả về list entity theo thứ tự xuất hiện.

    Chiến lược tránh overlap giữa CCCD và STK:
    - Chạy VN_BANK_ACCOUNT (STK) TRƯỚC — dùng keyword "STK" làm anchor
    - Chạy VN_CCCD sau — _remove_overlaps sẽ loại bỏ CCCD trùng với STK
    - Lý do: STK có thể là 12 chữ số (nhầm thành CCCD nếu CCCD chạy trước)
    - Phone/Email không conflict với CCCD/STK nên thứ tự không quan trọng
    """
    entities: list[dict] = []

    # --- 1. VN_BANK_ACCOUNT trước (ưu tiên: có keyword "STK" rõ ràng) ---
    # Group 1 là dãy số thực sự (không tính keyword)
    for m in _BANK_KEYWORD_RE.finditer(text):
        num_start = m.start(1)   # vị trí bắt đầu của số (group 1)
        num_end   = m.end(1)     # vị trí kết thúc của số
        entities.append({"type": "VN_BANK_ACCOUNT", "start": num_start, "end": num_end})

    # --- 2. VN_CCCD (12 chữ số) — sau STK để overlap removal ưu tiên STK ---
    for m in _CCCD_RE.finditer(text):
        entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # --- 3. VN_PHONE (0 + 9 số = 10 số) ---
    for m in _PHONE_RE.finditer(text):
        entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    # --- 4. EMAIL ---
    for m in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # --- Lọc bỏ overlap: nếu 2 entity chồng nhau, giữ entity xuất hiện trước ---
    entities = _remove_overlaps(entities)

    # Sắp xếp theo vị trí xuất hiện
    entities.sort(key=lambda e: e["start"])
    return entities


def _remove_overlaps(entities: list[dict]) -> list[dict]:
    """Loại bỏ các entity chồng lấp: giữ entity xuất hiện trước trong danh sách.

    Vì STK được thêm trước CCCD trong detect(), khi một số 12 chữ số vừa là
    STK vừa khớp CCCD regex, entity STK sẽ được giữ lại (đúng semantics).
    """
    kept: list[dict] = []
    for candidate in entities:
        overlap = False
        for existing in kept:
            # Kiểm tra overlap: [start1, end1) và [start2, end2) chồng nhau?
            if candidate["start"] < existing["end"] and existing["start"] < candidate["end"]:
                overlap = True
                break
        if not overlap:
            kept.append(candidate)
    return kept


# ---------------------------------------------------------------------------
# Bước 3a.3 — Hàm redact()
# ---------------------------------------------------------------------------
def redact(text: str) -> str:
    """Che PII trong text bằng [REDACTED_<TYPE>].

    Thay từ cuối về đầu văn bản để offset không bị lệch sau mỗi lần thay.
    Ví dụ: "CCCD: 012345678912, SĐT: 0912345678"
         → "CCCD: [REDACTED_VN_CCCD], SĐT: [REDACTED_VN_PHONE]"
    """
    entities = detect(text)
    # Sắp xếp từ cuối về đầu để thay thế không làm lệch offset
    for entity in sorted(entities, key=lambda e: e["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + replacement + text[entity["end"] :]
    return text
