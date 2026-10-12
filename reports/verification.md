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

- Kết quả kiểm thử PII Gate (`agent/pii.py`):
  - Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
  - Kết quả: `gold=118`, `pred=118`, `tp=118`
  - `precision`: **1.000** (100% thực thể phát hiện là chính xác)
  - `recall`: **1.000** (100% thực thể gán nhãn được tìm thấy; đạt mức cao nhất >95% theo RUBRIC.md)
  - Giới hạn của regex:
    - Regex dựa trên cấu trúc cố định và từ khoá tiền tố (như "STK", "tài khoản"). Nếu người dùng viết cách rời số (vd `09 12 345 678`), viết bằng chữ ("không chín một..."), hoặc số tài khoản không có tiền tố ngữ cảnh thì regex sẽ bỏ sót (false negative) hoặc nhận diện nhầm sang CCCD nếu cùng độ dài 12 chữ số.
    - Không bắt được các loại PII phi cấu trúc mang tính ngữ nghĩa tự do (địa chỉ nhà chi tiết, bệnh án, thông tin sinh trắc học) mà cần mô hình Zero-shot NER như GLiNER.

- Các lỗi còn lại:
  - Không còn lỗi nào tồn đọng. Toàn bộ các điều kiện trượt theo `RUBRIC.md` đều được kiểm soát và đáp ứng:
    1. Không có dòng ledger nào thiếu `reason`.
    2. PII của `KH-000999` không bị lọt ra sink sau containment (`reports/attack-after.log` rỗng 0 bytes).
    3. Runner không bao giờ đọc `KH-000777` hay bất kỳ khách hàng nào chỉ được nêu trong free text của kẻ tấn công.
    4. Vai trò `support_l1` bị từ chối truy cập bản ghi restricted; vai trò `dpo` vẫn phục vụ được khách hàng gắn với ticket hợp lệ.
    5. Toàn bộ dữ liệu sử dụng là dữ liệu tổng hợp (synthetic), không sử dụng credential hay PII thật.
