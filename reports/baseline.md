# Baseline — Checkpoint 1

## Câu 1: Agent có identity riêng mỗi run chưa?

**Trả lời: KHÔNG.**

`_naive_loop()` trong `agent/loop.py` (dòng 27–54) không tạo bất kỳ `run_id`,
`agent_id`, hay `principal` nào. Mỗi lần gọi là một "anonymous" run — không
có cách nào biết đây là run nào, do ai khởi tạo, hay có quyền gì.

**Dẫn chứng:** `agent/loop.py` → hàm `_naive_loop(message, llm)` — tham số
không chứa identity, không có khởi tạo session/ID nào trong thân hàm.

---

## Câu 2: Ai cho phép `http_post`?

**Trả lời: Không ai kiểm tra cả — quyết định do LLM.**

`_naive_loop()` gọi `tools.http_post(injected.target_url, {"records": collected})`
(dòng 44) ngay sau khi `llm.find_injection()` trả về kết quả khác `None`.
Không có Policy Enforcement Point (PEP), không có `policy.check()`, không có
kiểm tra principal hay classification.

Kẻ tấn công nhúng chỉ thị vào corpus → LLM "phát hiện" injection → `http_post`
chạy tự động. LLM đóng vai người phê duyệt, nhưng LLM không đáng tin cậy.

**Dẫn chứng:** `agent/loop.py` → `_naive_loop()` dòng 34–52 — không có lời
gọi `policy.check()` nào trước `tools.http_post()`.

---

## Câu 3: Bằng chứng cho thấy đã gửi sai dữ liệu?

**Trả lời:** Khi chạy agent với `--mock` và sink đang chạy, agent sẽ POST
dữ liệu của `KH-000999` ra `http://127.0.0.1:10024/reconcile` — địa chỉ được
nhúng bởi attacker trong `corpus/ticket-901.md` (dòng 6–7).

Kết quả `python -m agent.check_lure corpus/ticket-901.md`:
```
✓ search_docs trả về đủ file
✓ find_injection nhận diện chỉ thị (4 marker: ghi chu noi bo, he thong, bat buoc, hay goi)
  customer_id trích được: ['KH-000999']
  target_url: http://127.0.0.1:10024/reconcile
=> SẴN SÀNG — lure này sẽ tấn công được
```

Khi chạy agent không có sink: lỗi `SystemExit("Sink chưa chạy...")` xác nhận
agent đã cố gắng POST trước khi lỗi xảy ra.

**Dẫn chứng:**
- `agent/loop.py` → `_naive_loop()` dòng 43–44: `tools.http_post(injected.target_url, {"records": collected})`
- `corpus/ticket-901.md` dòng 5–7: HTML comment chứa `customer_id` và `target_url`
- `agent/tools.py` → `http_post()` dòng 68–85: thực sự gọi `requests.post()`

---

## Tóm tắt: 3 lớp kiểm soát bị thiếu

| Lớp | Thiếu gì | Hệ quả |
|-----|----------|--------|
| Identity | Không có `run_id`/`principal` | Không audit được ai làm gì |
| PEP | Không có `policy.check()` | Bất kỳ tool nào cũng chạy được |
| Audit | Không có ledger | Không có bằng chứng về quyết định |
