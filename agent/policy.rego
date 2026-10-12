package agent.policy

default allow = false
default reason = "DENY: Default deny by OPA policy"

# 1. Rule tối thiểu: data_classification == restricted và egress_enabled
deny_reasons[msg] {
    input.data_classification == "restricted"
    input.egress_enabled == true
    msg := "DENY: Data classification 'restricted' with egress enabled violates exfiltration policy."
}

# 2. TTL / Expiration check
deny_reasons[msg] {
    input.expires_at != ""
    time.parse_rfc3339_ns(input.expires_at) < time.now_ns()
    msg := sprintf("DENY: Context expired at %v.", [input.expires_at])
}

# 3. Principal Identity check
deny_reasons[msg] {
    input.principal_id == ""
    msg := "DENY: Missing principal identity."
}

deny_reasons[msg] {
    input.principal_id != ""
    not data.principals[input.principal_id]
    msg := sprintf("DENY: Unknown principal identity '%v'.", [input.principal_id])
}

# 4. Purpose check
deny_reasons[msg] {
    input.principal_id != ""
    principal := data.principals[input.principal_id]
    input.request_purpose != ""
    not array_contains(principal.purposes, input.request_purpose)
    msg := sprintf("DENY: Purpose '%v' is not authorized for principal '%v'.", [input.request_purpose, input.principal_id])
}

# 5. Effective Scopes & Tool check
deny_reasons[msg] {
    input.requested_tool == ""
    msg := "DENY: No requested_tool specified."
}

deny_reasons[msg] {
    input.principal_id != ""
    principal := data.principals[input.principal_id]
    input.requested_tool != ""
    not array_contains(principal.allowed_tools, input.requested_tool)
    msg := sprintf("DENY: Tool '%v' is not in allowed_tools for principal '%v'.", [input.requested_tool, input.principal_id])
}

deny_reasons[msg] {
    count(input.agent_scopes) > 0
    input.requested_tool != ""
    not array_contains(input.agent_scopes, input.requested_tool)
    msg := sprintf("DENY: Tool '%v' is not within agent scopes.", [input.requested_tool])
}

# 6. Delegation check
deny_reasons[msg] {
    input.delegation_depth > 0
    input.requested_tool != ""
    not array_contains(input.parent_scopes, input.requested_tool)
    msg := sprintf("DENY: Tool '%v' exceeds parent scopes during delegation.", [input.requested_tool])
}

array_contains(arr, elem) {
    arr[_] == elem
}

allow {
    count(deny_reasons) == 0
}

reason = msg {
    count(deny_reasons) > 0
    msg := deny_reasons[0]
} else = msg {
    msg := sprintf("ALLOW: Action '%v' permitted for principal '%v' under OPA policy.", [input.requested_tool, input.principal_id])
}
