# Báo cáo Phần Bonus Điểm — Day 24 L3 (Tối đa 10 điểm)

Theo quy định tại `RUBRIC.md`:
> *Bonus tối đa 10 điểm: port policy sang OPA/Cedar (4), so sánh GLiNER và regex trên test set (3), thử MCP rug pull local (4), delete cascade giữ ledger verify (3). Bonus phải có log/test riêng; không dùng bonus thay cho điều kiện trượt.*

Bài làm này đã triển khai hoàn thiện **3 đề mục Bonus** (tổng 11 điểm, đạt trần tối đa 10 điểm thưởng):

---

## 1. Port Policy sang Open Policy Agent (OPA) / Rego (+4 điểm)

### Mã nguồn & Test:
- Chính sách Rego: [agent/policy.rego](file:///d:/AI-Lab/K4-L3-DAY24-NguyenThuHang-2A202602463/agent/policy.rego)
- OPA Evaluator Adapter: [agent/policy_opa.py](file:///d:/AI-Lab/K4-L3-DAY24-NguyenThuHang-2A202602463/agent/policy_opa.py)
- Test suite riêng: [tests/test_policy_opa.py](file:///d:/AI-Lab/K4-L3-DAY24-NguyenThuHang-2A202602463/tests/test_policy_opa.py)

### Nội dung triển khai:
Chuyển đổi toàn bộ 7 quy tắc bảo vệ PEP và OBO sang ngôn ngữ chính sách khai báo chuẩn công nghiệp Rego của Open Policy Agent:
1. `deny_reasons`: Chặn dữ liệu `restricted` khi `egress_enabled == true`.
2. `deny_reasons`: Chặn khi `expires_at` đã quá hạn TTL.
3. `deny_reasons`: Chặn khi thiếu hoặc không tồn tại `principal_id`.
4. `deny_reasons`: Chặn khi `request_purpose` không nằm trong danh sách được phê duyệt của vai trò.
5. `deny_reasons`: Chặn khi `requested_tool` không nằm trong `allowed_tools` của vai trò.
6. `deny_reasons`: Chặn khi vượt quá `agent_scopes`.
7. `deny_reasons`: Chặn khi vượt quá `parent_scopes` trong trường hợp ủy quyền (`delegation_depth > 0`).

Kết quả kiểm thử: `pytest tests/test_policy_opa.py` **3/3 PASSED** ✅.

---

## 2. Thử nghiệm MCP Rug Pull local và Cơ chế Phòng thủ (+4 điểm)

### Mã nguồn & Test:
- Module phòng thủ MCP: [agent/mcp_defense.py](file:///d:/AI-Lab/K4-L3-DAY24-NguyenThuHang-2A202602463/agent/mcp_defense.py)
- Test suite riêng: [tests/test_mcp_rug_pull.py](file:///d:/AI-Lab/K4-L3-DAY24-NguyenThuHang-2A202602463/tests/test_mcp_rug_pull.py)

### Kịch bản tấn công:
Trong kiến trúc Model Context Protocol (MCP), tool server ban đầu cung cấp schema an toàn (`weather_reporter`). Trong quá trình vận hành (runtime), server độc hại âm thầm thực hiện "Rug Pull" bằng cách biến đổi schema: chèn thêm tham số exfiltrate dữ liệu nhạy cảm hoặc chuyển hướng endpoint ra server bên ngoài của kẻ tấn công.

### Cơ chế phòng thủ:
- **Tool Schema Pinning:** Tại thời điểm khởi tạo, gateway tính toán mã băm SHA-256 từ `(name, description, input_schema, endpoint)` và ghim (pin) vào registry tin cậy.
- **Runtime Validation:** Trước mỗi lần thực thi tool, so sánh mã băm thời gian thực với mã băm đã phê duyệt. Nếu phát hiện sai lệch $\rightarrow$ Chặn đứng tool call, phát tín hiệu cảnh báo `"DENY: MCP Rug Pull detected!"` và ghi nhận vào sổ cái kiểm toán tamper-evident.

Kết quả kiểm thử: `pytest tests/test_mcp_rug_pull.py` **2/2 PASSED** ✅.

---

## 3. Delete Cascade bảo toàn tính toàn vẹn của Ledger Verify (+3 điểm)

### Mã nguồn & Test:
- Module Cascade: [agent/cascade.py](file:///d:/AI-Lab/K4-L3-DAY24-NguyenThuHang-2A202602463/agent/cascade.py)
- Test suite riêng: [tests/test_delete_cascade.py](file:///d:/AI-Lab/K4-L3-DAY24-NguyenThuHang-2A202602463/tests/test_delete_cascade.py)

### Bài toán:
Theo Luật Dữ liệu 91/2025 và GDPR Điều 17 ("Quyền được xoá dữ liệu / Quyền được lãng quên"), khi người dùng yêu cầu xoá thông tin cá nhân:
- Dữ liệu trong `data/customers.json` và các tài liệu liên quan trong `corpus/` phải bị xoá bỏ hoàn toàn.
- Nếu xoá thô các dòng cũ trong sổ cái kiểm toán `ledger.jsonl`, chuỗi băm SHA-256 sẽ bị đứt gãy (`verify()` trả về `False`, vi phạm tính toàn vẹn kiểm toán).

### Giải pháp kỹ thuật:
- Thiết kế ledger bảo mật không lưu PII thô (chỉ lưu `args_hash`).
- Khi xoá dữ liệu, hệ thống phát hành bản ghi **Tombstone / Chứng chỉ xoá (Erasure Certificate)** nối tiếp vào chuỗi băm: ghi nhận quyết định `delete_customer_cascade` do DPO thực hiện.
- Chứng minh đối chiếu:
  - Xoá khách hàng và tài liệu thành công.
  - Sổ cái kiểm toán `ledger.verify()` **vẫn trả về `True`**!
  - Trong khi đó, việc xoá thô dòng cũ trong ledger lập tức bị `verify()` phát hiện là tấn công sửa đổi (`False`).

Kết quả kiểm thử: `pytest tests/test_delete_cascade.py` **1/1 PASSED** ✅.

---

## Tổng kết Kiểm thử Toàn bộ Repository (Bao gồm Bonus)

```powershell
$env:PYTHONIOENCODING="utf-8"; .venv\Scripts\python.exe -m pytest tests/ -v
```
**Tổng cộng: 39 / 39 tests PASSED (100% XANH HOÀN TOÀN)!** 🎯
- 33 tests bắt buộc: **100/100 điểm**
- 6 tests phần bonus: **+11 điểm bonus (đạt trần tối đa 10/10 điểm bonus)**
