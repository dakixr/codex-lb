## ADDED Requirements

### Requirement: Unavailable WebSocket response owners permit verified client recovery
For Codex-native WebSocket continuations that fail before response creation or visible output because their previous-response owner is unavailable, the service SHALL permit account recovery from a prefix-verified full resend or a subsequent client-supplied unanchored context window, after account-neutral projection and validation. If the current request lacks eligible history, the service SHALL return a sanitized top-level WebSocket `error` with status 400 and `error.code = previous_response_not_found` so a compatible Codex client can resend its locally retained context. It MUST preserve file ownership, explicit handshake turn-state ownership, authorization requirements, API-key settlement ordering, and pending-response isolation. It MUST NOT persist new conversation payloads for this recovery.

#### Scenario: Client delta is followed by a full-context retry
- **GIVEN** a Codex continuation references an unavailable previous-response owner and has no complete replay body
- **WHEN** the proxy rejects the output-free request
- **THEN** the compatible client receives the sanitized previous-response recovery classifier
- **AND** a subsequent portable unanchored context window can select another eligible account without the old response anchor

#### Scenario: Native reconnect retains recovery without retaining prompts
- **GIVEN** a native client reconnects with the same session or thread alias and API-key scope after the recovery signal
- **WHEN** it resends its current local context without an anchor
- **THEN** the service SHALL exclude the unavailable account using the existing bounded continuity cache
- **AND** SHALL omit the exact retired body turn-state token on recovery and subsequent turns while preserving unrelated client metadata
- **AND** SHALL NOT grant this recovery authority to another API-key scope or an explicit handshake turn-state owner

#### Scenario: Verified full resend recovers during account selection
- **GIVEN** the proxy verifies the full input prefix and retained prior output of a portable client resend
- **WHEN** the previous-response owner is unavailable during selection
- **THEN** the replacement request excludes that owner and sends the portable full history without its old response ID or learned turn-state token
- **AND** the following turn uses the replacement response's continuity

#### Scenario: Unsafe owner-bound requests remain protected
- **WHEN** a request contains an uploaded-file owner, explicit handshake turn-state ownership, unsupported opaque state, unpaired tool history, or visible response output
- **THEN** the service MUST NOT move it across accounts by this recovery mechanism
- **AND** policy and authentication failures MUST NOT be converted into permission to bypass their restrictions

#### Scenario: Current native tool and telemetry shapes remain portable
- **WHEN** a full resend contains known string client tracing labels, namespaces of validated function/custom tools, or a boolean web-search external-access flag
- **THEN** portability validation SHALL accept and retain those fields
- **AND** unknown metadata, nested or hosted-tool namespaces, and malformed option types SHALL remain ineligible
