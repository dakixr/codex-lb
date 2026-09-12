# Codex request-body fixtures (provider portability)

The corpus the provider-portability gate classifies. It backs issue #2123
(subscription-exhaustion overflow to a designated Model Source) and closes
design v3 §16 item (i): "captured bodies replace the synthetic pair".

Normative contracts:
[`openspec/specs/compatibility-tooling`](https://github.com/Soju06/codex-lb/tree/main/openspec/specs/compatibility-tooling)
(the capture lane and its refusals) and
[`openspec/specs/model-source-routing`](https://github.com/Soju06/codex-lb/tree/main/openspec/specs/model-source-routing)
(what the corpus must record and what the gate must assert). Operator
walkthrough: [`docs/traffic-parity.md`](../../../docs/traffic-parity.md).

`provenance.json` is the machine-readable source of truth; the table below is
rendered from the same facts and `tests/unit/test_codex_body_fixtures.py` pins
the two against each other and against the files on disk, in both directions.

## Corpus

| File | Origin | Slug | Transport | Captured (UTC) | CLI version | Sanitisation |
|---|---|---|---|---|---|---|
| `captured_gpt55_standard_http.json` | captured | `gpt-5.5` | http | 2026-09-11 | codex-cli 0.154.0 | telemetry dropped, identifiers placeholdered, item ids placeholdered, operator text rewritten |
| `captured_gpt56sol_lite_http.json` | captured | `gpt-5.6-sol` | http | 2026-09-11 | codex-cli 0.154.0 | telemetry dropped, identifiers placeholdered, item ids placeholdered, operator text rewritten |
| `gpt55_standard_first_turn.json` | synthetic | `gpt-5.5` | http | — | — | none (pre-strip fixture) |
| `gpt56_lite_bundle.json` | synthetic | `gpt-5.6-sol` | http | — | — | none (pre-strip fixture) |

Two roles live side by side, distinguished by `carries_client_telemetry`:

* **Pre-strip** (`true`, the synthetic pair) — keeps the Codex telemetry on
  purpose, because its job is to feed `strip_source_telemetry`. The privacy
  gate exempts *only* the bare telemetry key names for these two; a live UUID,
  a workspace path, an email address or a credential shape is still rejected.
* **Sanitised** (`false`, the captured pair) — a committable capture. Every
  privacy pass applies, unexempted.

## Recorded verdicts (and why they are declines)

The gate asserts the verdict `provenance.json` records, so a real body that
cannot overflow is green *and states that fact* instead of forcing a red CI or
a fake pass.

| Fixture | View | Verdict with the declared tool types |
|---|---|---|
| `captured_gpt55_standard_http.json` | admitted | `not_portable_tools` / `tool_search` |
| `captured_gpt56sol_lite_http.json` | `not_portable_lite_namespace` / `reasoning.context` | `not_portable_lite_namespace` / `additional_tools` |
| `gpt55_standard_first_turn.json` | admitted | portable |
| `gpt56_lite_bundle.json` | `not_portable_lite_namespace` / `reasoning.context` | `not_portable_lite_namespace` / `additional_tools` |

**Native Codex traffic cannot overflow today.** The captured gpt-5.5 body
declines even when the source model declares `custom`, `tool_search` *and*
`web_search`, for three independent reasons:

1. The real `tool_search` declaration carries an `execution` field, and
   `replay_safety._STATELESS_TOOL_DECLARATION_FIELDS` admits exactly
   `{description, type}`. Declaring the type cannot help.
2. The real `web_search` declaration carries `external_web_access` and
   `search_content_types`, outside
   `_ACCOUNT_NEUTRAL_TOOL_DECLARATION_FIELDS["web_search"]`.
3. Every input item carries a prefixed `id` (Codex mints them deliberately),
   and `responses_input_items_are_self_contained_fresh_replay` rejects any
   non-empty item id, so `transcript_is_source_free` is false. The overflow
   decision runs before `strip_input_item_ids`, which is release-direction
   only.

Closing those three gaps is production work, not fixture work: it changes
`replay_safety` and the overflow decision order. It is tracked separately, and
`add-subscription-overflow-model-source/design.md` decision 21 states the
`{type, description?}` declaration shape as a design premise that these
captures falsify.

## Where the synthetic pair diverges from Codex 0.154.0

The synthetic bodies are shape-illustrative, not byte-faithful. They are kept
because the projection unit tests exercise specific paths through them (an
admitted view, a telemetry strip that empties `stream_options`, a Lite decline)
that a real capture no longer reaches. Cite the captured pair for ground truth.

| Field | Synthetic | Real 0.154.0 |
|---|---|---|
| `stream_options` | present | **absent** on both real bodies |
| `stream_options.reasoning_summary_delivery` | `sequential_cutoff` (corrected) | the enum has only that one value; `interleaved` is unemittable |
| `parallel_tool_calls` (5.5) | `true` (corrected) | `true` |
| `reasoning` (5.5) | `{effort, summary}` | `{effort}` — no `summary` |
| `tools` (5.5) | `shell`, `update_plan`, `apply_patch`, `view_image` | `exec_command`, `write_stdin`, `request_user_input`, custom `apply_patch`, `view_image`, `tool_search`, `web_search` |
| `<environment_context>` | `cwd`, `approval_policy`, `sandbox_mode`, `network_access`, `shell` | `cwd`, `shell`, `current_date`, `timezone`, `filesystem/workspace_roots/root`, `permission_profile` |
| Lite `additional_tools` | `functions(exec, wait)`, `web`, `image_gen` | `functions(exec, wait, request_user_input)`, `collaboration` (6 tools); no `web`/`image_gen` in this lane |
| Lite prefix | 1 developer + 2 user | 4 developer + 2 user |
| Lite `instructions` | `""` | **absent** |
| Input-item `id` | absent (5.5) | present on every item |
| `text.verbosity` | `medium` | `low` |

The Lite `instructions` row is load-bearing for the gate: a real Lite body has
no `instructions` key, so `ResponsesRequest.model_validate` fails with
`instructions Field required`. Production survives because
`api._has_openai_responses_shape` returns true for `input`-without-
`instructions` and the request is validated as `openai_compat`. Any
fixture-shape test must therefore go through
`normalize_responses_request_payload(payload, openai_compat=_has_openai_responses_shape(payload))`.

## Capture a new body

One command. No ChatGPT credentials, no upstream contact, no quota:

```bash
uv run python -m scripts.traffic_analysis.codex_body_capture \
  --model gpt-5.5 --model gpt-5.6-sol --transport http \
  --out /mnt/scratch/tmp/codex-body-capture-$(date -u +%Y%m%d)
```

The script re-executes itself inside an unprivileged network namespace
(`unshare --map-root-user --net`), brings up loopback only, serves the pinned
catalog and a Responses lifecycle from an in-process origin, and runs
`codex exec` against it with a throwaway `CODEX_HOME` and a disposable
provider token. External egress is kernel-impossible, not merely unconfigured —
and the run proves it rather than asserting it: it asks the kernel for this
namespace's interfaces and refuses to capture if anything but loopback answers.
The observed list goes into the manifest as `network_isolation`.

`uv run` is load-bearing: the origin is FastAPI plus uvicorn and the request
decoder is `zstandard`, so a bare system interpreter fails at import — and on
many hosts `python` is not a command at all. The tools need codex-lb
*importable*, not configured: they read no settings and touch no database.

Expected output:

```text
network isolation: loopback only (observed interfaces: lo)
capture origin: http://127.0.0.1:19090/v1 (health ok)
catalog: codex-models-20260911.json sha256=de111010...
codex: codex-cli 0.154.0
captured gpt-5.5          http 35357 B sha256=2f851811... exit=0
                 keys=client_metadata,include,input,instructions,model,...
                 tools=['custom', 'function', 'tool_search', 'web_search'] ... instructions=present
captured gpt-5.6-sol      http 42491 B sha256=03eaf127... exit=0
                 tools=None items=['additional_tools/developer', ...] instructions=ABSENT
wrote: .../{body,headers,prewarm}-*.json, manifest.json
```

Byte counts move between runs — the session identifier and cache key differ —
so compare the key list, the tool types and the item sequence, not the sizes.

`--transport websocket` works the same way and is verified end to end against
0.154.0. The origin serves both transports because the generated provider only
*offers* websockets and the client decides; the websocket lane primes the
context with a `generate: false` frame before sending the turn, so the capture
keeps the frame carrying the transcript as the body and writes the prewarm to a
separate `prewarm-*.json`. Keep both when capturing a Lite body: its turn frame
is ~8 KB with no `additional_tools` item, because the tool bundle travelled in
the prewarm. The artifact name and the manifest record the transport the body
arrived on, so an HTTP fallback is never reported as a websocket capture. A
websocket body is persisted verbatim with its frame envelope, which the
sanitiser removes (`websocket_envelope_dropped`).

The two committed captures are HTTP, where Codex sends exactly one POST that
carries both the transcript and the tool surface — which is why they are the
corpus and the websocket lane is a tool, not a second fixture pair.

The catalog must be pinned: the Codex model manager invalidates its cache on a
`client_version` mismatch, so every run refetches `/models` from the provider's
base URL. `--catalog` defaults to
[`scripts/traffic_analysis/catalogs/codex-models-20260911.json`](../../../scripts/traffic_analysis/catalogs/README.md),
the committed catalog that produced this corpus — its SHA-256 is the
`catalog_sha256` below, and the gate pins the two against each other, so anyone
can reproduce a capture and verify the recorded digest. To capture a different
model set, pass a Codex `/models` response (the shape Codex caches as
`$CODEX_HOME/models_cache.json`) and record its digest. The catalog does not
fully determine the body — 0.154.0 layers bundled `model_info` overrides on top
of it, which is why the CLI version is the primary provenance key and the
catalog digest is secondary.

The script refuses, before starting anything, an output directory inside the
repository or under a temporary filesystem, an exported `CODEX_HOME` holding
an `auth.json`, a shell carrying `CODEX_LB_*` / `OPENAI_API_KEY` /
`OPENAI_BASE_URL` / `CHATGPT_BASE_URL` / `CODEX_ACCESS_TOKEN` /
`CODEX_API_BASE_URL` / `CODEX_SESSION_ID`, a shell carrying any outbound proxy
variable (`HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `WS_PROXY` / `WSS_PROXY`
/ `SOCKS_PROXY` / `FTP_PROXY` / `NO_PROXY`, either spelling), a non-loopback
origin, and a repository config file or `.env` passed as the catalog. It also
refuses a namespace that is not loopback-only, which can only be checked from
inside it and therefore fires in the re-executed child — still before the
capture directory, the origin or `codex` exist.

The proxy refusal is load-bearing: the Codex client routes even its loopback
POST through `HTTP_PROXY` and does not bypass `127.0.0.1`, so a proxied shell
captures nothing — and with `--no-network-namespace` it would ship the whole
request body to the proxy host instead.

## Pre-commit checklist

1. Sanitise: `uv run python -m scripts.traffic_analysis.codex_body_sanitize --in <body> --out tests/fixtures/codex_bodies/<name>.json --headers-in <headers> --headers-out <scratch>/headers.json --emit-redactions <scratch>/redactions.json`
2. Gate the corpus: `uv run python -m scripts.traffic_analysis.fixture_privacy_scan --root tests/fixtures/codex_bodies --strict`. It exits 0 on a pristine tree; the bodies allowed to keep bare telemetry key names are read from `provenance.json` (`carries_client_telemetry`) and printed, so no flags are needed.
3. Sanity-scan the scratch directory *without* `--strict`. The raw body, the
   header sidecar and the manifest all report findings by construction — that
   is the reminder to delete them (step 9), not a gate.
4. Diff the sanitised body against the raw one and confirm only telemetry,
   paths, dates and identifiers changed.
5. Read `instructions` and the developer prefix for `<skills_instructions>`
   skill-root paths and for the operator's installed skill names — the biggest
   real leak, and the one no credential scanner has vocabulary for. A transcript
   that contains tool calls carries the same text in `function_call.arguments`
   and `function_call_output.output`; the sanitiser rewrites those too, and the
   gate flags any environment tag or skill inventory left holding a
   non-placeholder value.
5b. Read the `tools` array. It is byte-preserved, so the sanitiser never
   rewrites it, and a tool description supplied by an MCP server the operator
   runs is the one place an absolute path can reach a fixture unrewritten. The
   gate reports it as `operator_path` rather than letting it through, which
   means the fix is to drop or edit the declaration by hand, not to re-run the
   sanitiser.
6. Add the `provenance.json` entry and the table row above: origin, slug,
   transport, UTC date, `codex --version`, catalog sha256, sanitisation list,
   expected view and expected verdict.
7. `uv run pytest -p no:cacheprovider -q tests/unit/test_codex_body_fixtures.py tests/unit/test_codex_body_sanitizer.py tests/unit/test_codex_body_capture_guards.py tests/unit/test_codex_body_capture_origin.py tests/unit/test_model_sources_projection.py tests/unit/test_replay_safety_portability.py`
8. `ruff check`, `ruff format`, `ty check`.
9. Delete the raw capture directory in the same session. Never commit a
   `headers-*.json` (it holds the `authorization` line even when the token was
   disposable) or a raw `body-*.json` / `prewarm-*.json`.

## Limitations

* Only an uncredentialed capture is covered. A ChatGPT-authenticated capture
  would add account headers, possibly `service_tier` and `access_programs`, the
  real upstream catalog and the operator's real skills — none of which the
  body-level gate reads, at the cost of a real upstream request and quota.
  Recorded as a deliberate v1 limitation.
* The host/account identity pass recognises an account or host name by the
  *shape* that makes it one — `jane@build-box` (shell prompt, ssh target,
  email), `~jane/` (home directory), `HOSTNAME=build-box` (and `USER`,
  `USERNAME`, `LOGNAME`, `HOST`). A bare mention in free text — "deploy to
  claw" — is not detectable by shape and is left to the review step above.
  Absolute paths, including `/home/<user>` and `C:\Users\<user>`, are covered by
  the path rule on every machine.
* Neither the sanitiser nor the gate reads `socket.gethostname()` or
  `getpass.getuser()`, so the fixture a capture sanitises to, and the verdict
  the gate reaches, are the same on every machine. The pass this replaced
  matched a bare word taken from the running box: 36 of 57 plausible host names
  red-lined the *pristine* corpus (`repo` hit all four fixtures) with no flag to
  clear the finding, and on a host called `exec` the sanitiser rewrote Codex's
  own `functions.exec` tool namespace. The gate test tries all 57.
* The absolute-path rule is a shape, not a list of roots, so `/srv`, `/opt`,
  `/data`, `/u`, `/Volumes`, `C:\Users\…` and the devcontainer default
  `/root/<repo>` are all the operator's. Two whole paths are cleared by value
  because Codex itself emits them — `/abs/path/…`, the documentation
  placeholder in its base instructions, and `/root/taskN[/task_M]`, the
  `spawn_agent` agent-task namespace. A Codex vocabulary path this list has not
  met yet shows up as a red gate on a fresh capture, never as a committed leak.
* The identifier scan covers `*.json` bodies. Prose (`*.md`) and
  `provenance.json` are reviewed by a human; credential shapes are still
  rejected in every file.
