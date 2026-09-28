## Context

An affected CLI 0.158 conversation repeatedly received `previous_response_owner_unavailable` after its WebSocket account exhausted quota. Codex recognizes `previous_response_not_found` and retries from its local full history. The proxy already retains a count and fingerprint that can verify a subsequent full resend, but selection-time owner failure occurs before existing replay logic.

## Goals / Non-Goals

Recover portable conversations on an eligible account without persisting prompts. Keep partial, file-owned, explicit turn-state, policy, and already-visible requests subject to their existing ownership rules. Do not implement the unwired durable transcript reconstruction library or promise recovery for opaque compaction or missing local history.

## Decisions

Extend upstream #2398's projection and settlement fixes. At selection-time owner loss, use the same verified account-switch preparation and select a replacement excluding the unavailable owner. Ensure the replacement connection and sent body both use the prepared fresh request, without the old socket's turn-state token. If no complete body is available, expose the sanitized standard previous-response classifier to compatible Codex clients before visible output, allowing their existing retry to supply the missing context. Preserve internal owner-unavailable diagnostics.

The client retry is a new unanchored request: its input is the authoritative current context window, including any local plain-text compaction. Validate and project that whole window rather than demanding the old pre-compaction prefix. Requests retaining an anchor cannot claim that authority. Store only the unavailable account ID and retired body turn-state token in the existing bounded, API-key-scoped continuity cache. Native session/thread aliases carry this state over the CLI reconnect. Clear the unavailable account on successful completion; retain the retired token so the client's OnceLock cannot send it on the following turn. Explicit handshake turn-state ownership remains hard.

Codex 0.158 sends client session/thread/turn tracing labels and namespaced local tools. Allow only known string telemetry fields, namespaces of already validated function/custom tools, and a boolean web-search external-access flag. Unknown metadata and hosted account-owned tools remain rejected. Preserve these declarations in the upstream body; validation does not remove tools or client conversation content.

## Risks / Trade-offs

Changing an error code is insufficient unless the next full resend can leave the unavailable owner. Tests must cover the complete two-request recovery and subsequent continuation. Strict replay projection can still refuse unsupported opaque state; this is preferable to dropping conversation context. Client recovery uses its existing bounded retry budget. Same-account retries retain their original payload. No additional payload retention is introduced.
