# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản:
  Gitleaks v8.30.1.

- Commit chứa token giả:
  `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c` — chore: seed student lab with synthetic secret exercise).

- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt`
  - Rule ID: `lab24-synthetic-token` (cấu hình trong `.gitleaks.toml`: regex `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`)
  - Giá trị tìm thấy: `LAB24_FAKE_TOKEN=LAB24-DEMO-7K2Q9M4R6T8V1X3Z`
  - Lệnh quét lịch sử: `gitleaks git --config .gitleaks.toml --redact --verbose .` báo 1 finding vi phạm rule `lab24-synthetic-token` tại commit `1bdd849`.

- Kết quả quét file hiện tại:
  - Quét thư mục làm việc hiện tại bằng `gitleaks dir --config .gitleaks.toml .` cho kết quả sạch (0 leaks, exit code 0) do file `lab-fake-secret.txt` đã được xoá bỏ khỏi HEAD tại commit `ece6ca4`.

- Nếu đây là credential thật, cần xử lý thế nào:
  - Lập tức thu hồi (revoke) và xoay vòng (rotate) credential trên hệ thống cấp quyền hoặc nhà cung cấp dịch vụ tương ứng.
  - Rà soát access logs và audit trail của credential xem đã có dấu hiệu truy cập bất thường hay khai thác trái phép hay chưa.
  - Ban hành secret mới và lưu trữ trong hệ thống Secrets Manager (hoặc biến môi trường bảo mật), tuyệt đối không lưu trong mã nguồn.

- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file khỏi HEAD chỉ loại bỏ file ở commit mới nhất, nhưng secret vẫn tồn tại nguyên vẹn trong toàn bộ lịch sử Git (`git commit history`, packfiles, reflog). Kẻ tấn công clone repo về vẫn có thể dùng `git show 1bdd849` để trích xuất secret.
  - Pin dependency (bằng sha256 hash trong `requirements.lock`) và cài pre-commit hook chỉ giúp bảo vệ tính toàn vẹn gói phụ thuộc và ngăn chặn việc vô tình đẩy thêm secret mới vào repo trong tương lai, nhưng không làm vô hiệu hoá credential đã bị lộ lọt. Biện pháp triệt để duy nhất là thu hồi và rotate secret trên hệ thống đích.
