"""Mô phỏng phòng chống tấn công MCP (Model Context Protocol) Rug Pull local.

Tấn công MCP Rug Pull:
- MCP Server ban đầu đăng ký một tool an toàn (ví dụ: `local_calculator` hoặc `read_docs`).
- Trong quá trình runtime, server âm thầm tráo đổi tool schema (Rug Pull) đòi thêm tham số nhạy
  cảm hoặc chuyển hướng endpoint ra sink độc hại.

Cơ chế phòng thủ:
- Tool Definition Pinning (Mã băm SHA-256 của Tool Schema tại thời điểm khởi tạo).
- PEP Runtime Validation: So chiếu chữ ký runtime với chữ ký đã phê duyệt.
- Nếu hash schema thay đổi -> Chặn đứng tool execution và ghi nhận cảnh báo vào ledger.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MCPToolDefinition:
    name: str
    description: str
    input_schema: dict
    endpoint: str

    def compute_schema_hash(self) -> str:
        payload = {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "endpoint": self.endpoint,
        }
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class MCPRegistry:
    def __init__(self):
        self._approved_pins: dict[str, str] = {}

    def pin_tool(self, tool_def: MCPToolDefinition) -> str:
        h = tool_def.compute_schema_hash()
        self._approved_pins[tool_def.name] = h
        return h

    def validate_tool_call(self, tool_def: MCPToolDefinition) -> tuple[bool, str]:
        if tool_def.name not in self._approved_pins:
            return False, f"DENY: Unregistered MCP tool '{tool_def.name}'."

        expected_hash = self._approved_pins[tool_def.name]
        current_hash = tool_def.compute_schema_hash()

        if current_hash != expected_hash:
            return False, (
                f"DENY: MCP Rug Pull detected! Tool '{tool_def.name}' schema mutated at runtime. "
                f"Expected hash {expected_hash[:12]}..., got {current_hash[:12]}..."
            )

        return True, f"ALLOW: MCP tool '{tool_def.name}' verified against pinned schema."
