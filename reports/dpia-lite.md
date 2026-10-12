# DPIA-lite — điền trong checkpoint 5

### 1. Loại dữ liệu và phân loại:
- **Dữ liệu công khai/nội bộ (`internal`):** Nội dung các ticket yêu cầu hỗ trợ khách hàng trong thư mục `corpus/*.md`.
- **Dữ liệu cá nhân nhạy cảm (`restricted`):** Hồ sơ thông tin khách hàng trong `data/customers.json`, gồm: Họ tên (`name`), Số Căn cước công dân (`cccd`), Số điện thoại (`phone`), Số tài khoản ngân hàng (`bank_account`), Địa chỉ email (`email`), và liên kết ticket (`related_tickets`).
- **Phân loại bảo vệ:** Phân loại theo 3 mức độ: `public`, `internal`, và `restricted`. Mọi thông tin khách hàng chứa định danh cá nhân hoặc tài chính đều thuộc diện `restricted` cần bảo vệ đặc biệt theo quy định pháp luật.

### 2. Mục đích xử lý và principal:
- **Mục đích xử lý (`request_purpose`):**
  - `summarize-tickets`: Tổng hợp nội dung các yêu cầu đang mở phục vụ quản lý vận hành.
  - `support-reply`: Hỗ trợ giải đáp và xử lý ticket cho khách hàng.
  - `billing-reconciliation`: Đối soát giao dịch, hoá đơn tài chính.
  - `privacy-audit`: Kiểm toán tuân thủ bảo vệ dữ liệu cá nhân.
- **Danh tính thực thi (`principal_id` theo `data/principals.json`):**
  - `support_l1` (Nhân viên hỗ trợ bậc 1): Chỉ được phép tra cứu tài liệu (`search_docs`), không được phép truy cập hồ sơ khách hàng (`read_customer`).
  - `billing` (Bộ phận kế toán / đối soát): Được tra cứu tài liệu và đọc khách hàng cho mục đích đối soát hoá đơn.
  - `dpo` (Cán bộ bảo vệ dữ liệu cá nhân): Được phép đọc tài liệu và hồ sơ khách hàng phục vụ xử lý yêu cầu hợp lệ và kiểm toán quyền riêng tư.

### 3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- **Run A (Xử lý nội dung không tin cậy):**
  - Nhận truy vấn người dùng `message`.
  - Gọi tool `search_docs` đọc các file markdown trong `corpus/`.
  - Giữ lại toàn văn document tại Run A để ngăn chặn rủi ro tiêm mã độc (prompt injection). Chỉ chuyển giao danh sách mã số ticket đã chuẩn hoá (`ticket_ids: list[int]`) trích xuất từ tên file sang Run B.
- **Run B (Truy xuất kho dữ liệu nhạy cảm):**
  - Nhận `ticket_ids` từ Run A, tra cứu trong `data/customers.json` thông qua trường tin cậy `related_tickets` để xác định `customer_id`.
  - Kiểm tra thẩm quyền qua Policy Enforcement Point (PEP). Nếu được phép, gọi `read_customer` để đọc hồ sơ.
- **Endpoint & Kênh truyền dữ liệu ra ngoài:**
  - Endpoint duy nhất trong môi trường lab: `http://127.0.0.1:10024/reconcile` (Sink server).
  - Tool gọi mạng: `http_post`.
  - Chính sách PEP chặn triệt để tool `http_post` khi dữ liệu là `restricted` và bật `egress_enabled`, ngăn chặn hoàn toàn việc rò rỉ dữ liệu qua endpoint này.

### 4. Bằng chứng deny/allow và giới hạn của mock:
- **Bằng chứng Allow & Chức năng hợp lệ:**
  - Principal `dpo` truy cập thành công thông tin khách hàng `KH-000999` gắn với ticket hợp lệ: được ghi nhận `decision = "allow"` trong `reports/ledger.jsonl`.
- **Bằng chứng Deny & Ngăn chặn rò rỉ:**
  - Principal `support_l1` bị chặn khi cố gắng đọc dữ liệu khách hàng: ghi nhận `decision = "deny"` trong ledger với lý do `Tool 'read_customer' is not in allowed_tools for principal 'support_l1'`.
  - Chỉ thị độc hại yêu cầu POST dữ liệu ra sink bị chặn đứng: ghi nhận `decision = "deny"` cho `http_post` trong ledger với lý do `Data classification 'restricted' with egress enabled violates exfiltration policy`.
  - Minh chứng đối chiếu: `reports/attack-before.log` bị lộ toàn bộ PII của `KH-000999` $\rightarrow$ `reports/attack-after.log` hoàn toàn rỗng (0 bytes).
- **Giới hạn của môi trường Mock:**
  - Dữ liệu sử dụng trong bài lab là dữ liệu tổng hợp (synthetic data), hoàn toàn không chứa thông tin cá nhân của người thật.
  - Sử dụng `MockLLM` dựa trên luật so khớp tất định nhằm đảm bảo tính tái lập trong chấm điểm tự động; mô hình thực tế cần bổ sung các cơ chế phòng thủ đa tầng (Semantic Guardrails, Human-in-the-loop).
  - Tùy chọn `--as` mô phỏng phân quyền ngữ cảnh OBO, không thay thế cho hệ thống xác thực người dùng thật (SSO, OAuth2, MFA) trong môi trường sản phẩm.
