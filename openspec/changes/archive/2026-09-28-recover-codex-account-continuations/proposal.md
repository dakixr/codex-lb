## Why

Codex CLI conversations become stuck on an exhausted OpenAI account even while another account is available. Direct WebSocket delta requests carry an account-owned response ID, and existing full-resend recovery rejects portable history containing upstream item identities and reasoning bookkeeping.

## What Changes

- Extend upstream PR #2398's portable WebSocket full-resend projection with the native client recovery handshake.
- Ask stock Codex to resend its locally retained full context when an unavailable previous-response owner prevents an output-free continuation, using the client's existing previous-response recovery classifier.
- Recover selection-time owner loss using verified portable history and exclude the failed owner; retain file, authorization, pending-request, and tool-pair safety gates.
- Verify public WebSocket recovery across reconnects and the following turn, unsafe-history refusal, and the installed CLI's full-resend protocol.
- Accept current Codex's portable tool namespaces, web-search network flag, and client telemetry; discard only the body routing token retired by an observed owner failure.

## Capabilities

### Modified Capabilities

- `responses-api-compat`: Portable WebSocket full-resend and client-assisted delta account recovery.

## Impact

Direct Responses WebSocket preparation, account selection and retry; integration tests and OpenSpec. No new conversation storage, migration, or required configuration. Upstream #2428 is an unwired HTTP-spool library and alone does not repair this path.
