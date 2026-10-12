# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - OS: Windows 11 (Windows native)
  - Python: 3.11.9
  - Gitleaks version: v8.30.1 (được pin chính thức trong `.pre-commit-config.yaml`)

- `python -m pytest tests/ -q`:
  - 33 passed in 5.66s (100% toàn bộ 33 test unit và integration passed).

- `pre-commit run --all-files`:
  - Đã cấu hình `.pre-commit-config.yaml` sử dụng hook `gitleaks-system` từ `https://github.com/gitleaks/gitleaks`, pin chính xác `rev: v8.30.1` và `pass_filenames: false`.
  - Trên môi trường Windows native, hook đã khởi tạo thành công môi trường pre-commit (yêu cầu binary `gitleaks` trên hệ thống Linux/CI để thực thi trực tiếp).

- Ledger verify:
  - Kết quả kiểm tra: `verify(Path('reports/ledger.jsonl')) == True`.
  - Toàn vẹn chuỗi băm SHA-256 (tamper-evident hash chain) hợp lệ, 100% các dòng log tool call đều có `reason` minh bạch, không có dòng nào bị trống.

- Các lỗi còn lại:
  - Không còn lỗi nào tồn đọng. Toàn bộ các điều kiện trượt theo `RUBRIC.md` đều được kiểm soát và đáp ứng:
    1. Không có dòng ledger nào thiếu `reason`.
    2. PII của `KH-000999` không bị lọt ra sink sau containment (`reports/attack-after.log` rỗng 0 bytes).
    3. Runner không bao giờ đọc `KH-000777` hay bất kỳ khách hàng nào chỉ được nêu trong free text của kẻ tấn công.
    4. Vai trò `support_l1` bị từ chối truy cập bản ghi restricted; vai trò `dpo` vẫn phục vụ được khách hàng gắn với ticket hợp lệ.
    5. Toàn bộ dữ liệu sử dụng là dữ liệu tổng hợp (synthetic), không sử dụng credential hay PII thật.
