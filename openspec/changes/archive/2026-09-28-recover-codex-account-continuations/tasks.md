## 1. Implementation

- [x] 1.1 Extend upstream #2398 while retaining projection, same-account behavior, and settlement ordering.
- [x] 1.2 Recover verified full resends on selection-time previous-response owner loss and preserve replacement body/header ownership.
- [x] 1.3 Expose Codex's full-context recovery classifier for eligible output-free owner-unavailable deltas.

## 2. Verification and delivery

- [x] 2.1 Test public WebSocket delta failure, full-context retry, replacement completion, and the following turn; cover protected and partial-history cases.
- [x] 2.2 Run focused regression suites, formatting/lint, architecture checks and strict OpenSpec validation.
- [x] 2.3 Sync verified requirements/context, archive the change, and record contribution validation in WORKLOG.md.
