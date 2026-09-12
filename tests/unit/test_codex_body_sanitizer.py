"""Sanitiser and fixture privacy gate, including the planted mutations (#2123).

Three groups:

* **Direction A (removal).** Every strip target is absent from the serialized
  output *bytes*, not merely from its own key -- the trap being that
  ``prompt_cache_key`` equals the session id and that turn metadata is a JSON
  string nested inside another string.
* **Direction B (preservation).** Every preserved field is byte-identical, and
  an absent field stays absent. Fabricating ``instructions`` or ``tools`` would
  change the recorded portability verdict, so absence is part of the contract.
* **Planted mutations.** Each one corrupts a ``tmp_path`` copy of the real
  corpus and asserts the gate rejects it. The committed fixtures are never
  mutated. The gate's own assertions are invoked rather than re-implemented: a
  reimplemented assertion would prove nothing about the gate that ships.
"""

from __future__ import annotations

import getpass
import json
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from scripts.traffic_analysis import codex_body_sanitize, fixture_privacy_scan
from scripts.traffic_analysis.codex_body_sanitize import (
    ALLOWED_TOP_LEVEL_FIELDS,
    DROPPED_TOP_LEVEL_FIELDS,
    PLACEHOLDERS,
    PRESERVED_TOP_LEVEL_FIELDS,
    SANITISED_TOP_LEVEL_FIELDS,
    SHAPE_PRESERVED_TOP_LEVEL_FIELDS,
    WEBSOCKET_ENVELOPE_FIELDS,
    Redaction,
    UnsanitisableBodyError,
    is_placeholder_uuid,
    placeholder_uuid,
    sanitize_body,
    sanitize_headers,
)
from tests.unit import test_codex_body_fixtures as gate

pytestmark = pytest.mark.unit

FIXTURES = gate.FIXTURES
CAPTURED_STANDARD = "captured_gpt55_standard_http.json"
CAPTURED_LITE = "captured_gpt56sol_lite_http.json"
SYNTHETIC_STANDARD = "gpt55_standard_first_turn.json"

_FIXED_IDENTITIES = ("capture-host-name", "capture-operator")

_LIVE_SESSION = "0199f2c1-2b3d-4e5f-8a9b-1c2d3e4f5a6b"
_LIVE_TURN = "0199f2c1-3c4e-5f60-9bac-2d3e4f5a6b7c"
_LIVE_INSTALLATION = "0199f2c1-4d5f-6071-acbd-3e4f5a6b7c8d"


@pytest.fixture(autouse=True)
def _fixed_identities(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin the host/account pass so the suite is machine-independent."""

    monkeypatch.setattr(codex_body_sanitize, "live_identity_strings", lambda: _FIXED_IDENTITIES)
    monkeypatch.setattr(fixture_privacy_scan, "live_identity_strings", lambda: _FIXED_IDENTITIES)
    yield


def _realistic_body() -> dict[str, Any]:
    """One body carrying every strip target and every preserve target.

    Modelled on the two captured bodies: the skills block and the AGENTS.md
    heading arrive as developer/user content, the environment context carries
    the 0.154.0 tag set, and the tool array mixes a function, a custom tool and
    the two declarations that make a real body decline.
    """

    return {
        "model": "gpt-5.5",
        "instructions": "You are Codex, a coding agent based on GPT-5.",
        "input": [
            {
                "type": "message",
                "role": "developer",
                "id": f"msg_{_LIVE_SESSION}",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "<skills_instructions>\n## Skills\nA skill is a set of local instructions.\n"
                            "### Skill roots\n- `r0` = `/home/operator/.codex/skills/.system`\n"
                            "### Available skills\n- imagegen: Generate images. (file: r0/imagegen/SKILL.md)\n"
                            "- private-runbook: Deploy the payroll service. (file: r0/private-runbook/SKILL.md)\n"
                            "</skills_instructions>"
                        ),
                    }
                ],
                "internal_chat_message_metadata_passthrough": {
                    "content_item_kinds": ["model.base_instructions"],
                    "turn_id": _LIVE_TURN,
                },
            },
            {
                "type": "message",
                "role": "user",
                "id": f"msg_{_LIVE_TURN}",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "# AGENTS.md instructions for /mnt/scratch/checkout\n\n"
                            "<INSTRUCTIONS>\nRun the unit tests.\n</INSTRUCTIONS>"
                        ),
                    },
                    {
                        "type": "input_text",
                        "text": (
                            "<environment_context>\n  <cwd>/mnt/scratch/checkout</cwd>\n"
                            "  <shell>zsh</shell>\n  <current_date>2026-09-11</current_date>\n"
                            "  <timezone>Europe/Berlin</timezone>\n"
                            "  <filesystem><workspace_roots><root>/mnt/scratch/checkout</root>"
                            "</workspace_roots></filesystem>\n</environment_context>"
                        ),
                    },
                    {
                        "type": "input_text",
                        "text": f"Reviewed by {_FIXED_IDENTITIES[1]} on {_FIXED_IDENTITIES[0]}.",
                    },
                ],
            },
        ],
        "tools": [
            {"type": "function", "name": "exec_command", "parameters": {"type": "object", "properties": {}}},
            {"type": "custom", "name": "apply_patch", "format": {"type": "text"}},
            {"type": "tool_search", "execution": "client", "description": "# Tool discovery"},
            {"type": "web_search", "external_web_access": True, "search_content_types": ["text"]},
        ],
        "tool_choice": "auto",
        "parallel_tool_calls": True,
        "reasoning": {"effort": "medium"},
        "text": {"verbosity": "low"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
        "stream": True,
        "prompt_cache_key": _LIVE_SESSION,
        "client_metadata": {
            "session_id": _LIVE_SESSION,
            "thread_id": _LIVE_SESSION,
            "turn_id": _LIVE_TURN,
            "x-codex-installation-id": _LIVE_INSTALLATION,
            "x-codex-turn-metadata": json.dumps(
                {"installation_id": _LIVE_INSTALLATION, "session_id": _LIVE_SESSION, "turn_id": _LIVE_TURN}
            ),
        },
        "access_programs": ["internal-preview"],
        "stream_options": {"reasoning_summary_delivery": "sequential_cutoff", "include_obfuscation": False},
    }


# --- direction A: removal -------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        _LIVE_SESSION,
        _LIVE_TURN,
        _LIVE_INSTALLATION,
        "/home/operator",
        "/mnt/scratch/checkout",
        "private-runbook",
        "Europe/Berlin",
        "2026-09-11",
        _FIXED_IDENTITIES[0],
        _FIXED_IDENTITIES[1],
    ],
    ids=[
        "session_id",
        "turn_id",
        "installation_id",
        "operator_path",
        "workspace_path",
        "skill_name",
        "timezone",
        "capture_date",
        "hostname",
        "account",
    ],
)
def test_no_strip_target_survives_anywhere_in_the_serialized_output(secret: str) -> None:
    """Checked against the output *bytes*: nested JSON-in-a-string hides from a key walk."""

    sanitised, redactions = sanitize_body(_realistic_body())

    assert secret not in json.dumps(sanitised), f"{secret} survived sanitisation"
    assert redactions


def test_every_placeholder_lands_verbatim_in_the_output() -> None:
    """Removal is not enough: the substitute must be the literal placeholder.

    Escaping a replacement string for a regex *pattern* still removes the
    secret while writing the escapes into the fixture (``2026\\-01\\-01``), so
    the value is asserted, not just the absence of the original.
    """

    sanitised, _ = sanitize_body(_realistic_body())
    environment = sanitised["input"][1]["content"][1]["text"]

    assert f"<cwd>{PLACEHOLDERS.workspace}</cwd>" in environment
    assert f"<current_date>{PLACEHOLDERS.date}</current_date>" in environment
    assert f"<timezone>{PLACEHOLDERS.timezone}</timezone>" in environment
    assert f"<shell>{PLACEHOLDERS.shell}</shell>" in environment
    assert f"<root>{PLACEHOLDERS.workspace}</root>" in environment
    assert "\\" not in environment
    skills = sanitised["input"][0]["content"][0]["text"]
    assert f"`r0` = `{PLACEHOLDERS.skill_root}`" in skills
    assert PLACEHOLDERS.skill_name in skills
    heading = sanitised["input"][1]["content"][0]["text"]
    assert heading.startswith(f"# AGENTS.md instructions for {PLACEHOLDERS.workspace}")
    identities = sanitised["input"][1]["content"][2]["text"]
    assert identities == f"Reviewed by {PLACEHOLDERS.account} on {PLACEHOLDERS.account}."


def test_telemetry_fields_go_whole_and_the_cache_key_becomes_a_placeholder() -> None:
    sanitised, _ = sanitize_body(_realistic_body())

    assert not DROPPED_TOP_LEVEL_FIELDS & set(sanitised)
    assert is_placeholder_uuid(sanitised["prompt_cache_key"])
    # The Codex key goes; a standard ``include_obfuscation`` stays, so the
    # object is not dropped -- exactly production's ``strip_source_telemetry``.
    assert sanitised["stream_options"] == {"include_obfuscation": False}


def test_stream_options_is_dropped_once_the_codex_key_empties_it() -> None:
    body = _realistic_body()
    body["stream_options"] = {"reasoning_summary_delivery": "sequential_cutoff"}

    sanitised, _ = sanitize_body(body)

    assert "stream_options" not in sanitised


def test_item_ids_are_replaced_not_removed_so_the_history_evidence_survives() -> None:
    """A non-empty prefixed id is what makes a native body decline as history."""

    sanitised, redactions = sanitize_body(_realistic_body())

    identifiers = [item["id"] for item in sanitised["input"]]
    assert identifiers == [f"msg_{placeholder_uuid(1)}", f"msg_{placeholder_uuid(2)}"]
    assert all(is_placeholder_uuid(identifier.removeprefix("msg_")) for identifier in identifiers)
    assert {redaction.kind for redaction in redactions} >= {"item_id_placeholder"}
    # The nested account-neutral ``turn_id`` is placeholdered, not deleted.
    passthrough = sanitised["input"][0]["internal_chat_message_metadata_passthrough"]
    assert is_placeholder_uuid(passthrough["turn_id"])
    assert passthrough["content_item_kinds"] == ["model.base_instructions"]


def test_strip_item_ids_removes_them_for_the_stripped_variant() -> None:
    sanitised, redactions = sanitize_body(_realistic_body(), strip_item_ids=True)

    assert all("id" not in item for item in sanitised["input"])
    assert {redaction.kind for redaction in redactions} >= {"item_id_stripped"}


def test_redactions_never_carry_the_removed_value() -> None:
    _, redactions = sanitize_body(_realistic_body())

    for redaction in redactions:
        assert _LIVE_SESSION not in redaction.path and _LIVE_SESSION not in redaction.kind
        assert "/home/operator" not in redaction.path


# --- direction B: preservation --------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    sorted(PRESERVED_TOP_LEVEL_FIELDS & set(_realistic_body())),
)
def test_every_preserved_field_is_byte_identical(field: str) -> None:
    body = _realistic_body()

    sanitised, _ = sanitize_body(body)

    assert json.dumps(sanitised[field]) == json.dumps(_realistic_body()[field]), field


def test_the_declaration_shapes_that_cause_the_declines_are_preserved_exactly() -> None:
    """``tool_search.execution`` and the real ``web_search`` fields are the evidence."""

    sanitised, _ = sanitize_body(_realistic_body())

    declarations = {tool["type"]: tool for tool in sanitised["tools"]}
    assert declarations["tool_search"]["execution"] == "client"
    assert declarations["web_search"]["external_web_access"] is True
    assert declarations["web_search"]["search_content_types"] == ["text"]


@pytest.mark.parametrize("absent", ["instructions", "tools", "stream_options"])
def test_an_absent_field_stays_absent(absent: str) -> None:
    """A real Lite body has no ``instructions``/``tools``; a real 5.5 body has no
    ``stream_options``. ``overflow_portability_view`` declines unknown top-level
    fields, so fabricating one would change the recorded verdict."""

    body = _realistic_body()
    del body[absent]

    sanitised, _ = sanitize_body(body)

    assert absent not in sanitised


def test_a_lite_additional_tools_bundle_is_byte_preserved() -> None:
    """Codex-generated, and the load-bearing evidence for ``not_portable_lite_namespace``.

    Its ``spawn_agent`` description documents agent task namespaces as
    ``/root/<task>``; a catch-all path rewriter destroyed exactly this text
    before the walk was scoped to message content.
    """

    bundle = {
        "type": "additional_tools",
        "role": "developer",
        "id": f"at_{_LIVE_SESSION}",
        "tools": [
            {
                "type": "namespace",
                "name": "collaboration",
                "tools": [
                    {
                        "name": "spawn_agent",
                        "description": "If your current task is `/root/task1` the agent is `/root/task1/task_3`.",
                    }
                ],
            }
        ],
    }
    body = _realistic_body()
    del body["tools"]
    body["input"] = [bundle, *body["input"]]

    sanitised, _ = sanitize_body(body)

    preserved = dict(sanitised["input"][0])
    assert preserved.pop("id") == f"at_{placeholder_uuid(1)}"
    expected = {key: value for key, value in bundle.items() if key != "id"}
    assert json.dumps(preserved, sort_keys=True) == json.dumps(expected, sort_keys=True)


_TOOL_CALL_LEAK = (
    "<skills_instructions>\n### Skill roots\n- `r0` = `/srv/acme/private-skills`\n"
    "### Available skills\n- acme-payroll-export: Export the ACME payroll ledger for a pay period.\n"
    "</skills_instructions>\n"
    "<environment_context><cwd>/srv/acme/ledger</cwd>"
    "<timezone>Asia/Seoul</timezone><shell>zsh</shell></environment_context>"
)


def _tool_call_transcript() -> dict[str, Any]:
    """A turn whose transcript is tool calls, which is what a second turn looks like."""

    return {
        "model": "gpt-5.5",
        "input": [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "shell",
                "arguments": json.dumps({"command": ["bash", "-lc", "cd /home/jane/clients/acme && ./deploy.sh"]}),
            },
            {"type": "function_call_output", "call_id": "call_1", "output": _TOOL_CALL_LEAK},
            {
                "type": "function_call_output",
                "call_id": "call_2",
                "output": [{"type": "output_text", "text": _TOOL_CALL_LEAK}],
            },
        ],
    }


def test_a_tool_call_transcript_is_rewritten_like_message_content() -> None:
    """The walk covers every text-bearing item field, not only ``content``.

    A ``function_call`` carries the command the agent ran and a
    ``function_call_output`` carries what it printed -- in both the string and
    the list-of-parts form. Walking only ``content`` left the operator's cwd,
    skill inventory and skill-root path in the fixture, with no redaction
    recorded to tell the reviewer to look.
    """

    sanitised, redactions = sanitize_body(_tool_call_transcript())

    assert [redaction.path for redaction in redactions] == [
        "input[0].arguments",
        "input[1].output",
        "input[2].output[0].text",
    ]
    serialized = json.dumps(sanitised)
    for leaked in ("/home/jane", "/srv/acme", "acme-payroll-export", "Asia/Seoul", "zsh"):
        assert leaked not in serialized
    assert PLACEHOLDERS.workspace in sanitised["input"][0]["arguments"]
    assert PLACEHOLDERS.skill_root in sanitised["input"][1]["output"]
    assert PLACEHOLDERS.timezone in sanitised["input"][2]["output"][0]["text"]


def test_a_tool_call_leak_no_longer_passes_the_privacy_gate_as_well(tmp_path: Path) -> None:
    """The second half of the same hole: the gate had no vocabulary for it either.

    None of the leaked strings is a path the gate knows, an identifier, an email
    or a credential shape, so an unsanitised tool-call output passed
    ``--strict`` too. The backstop is value-conditioned -- the sanitised body
    keeps the same tags and headings -- so it flags the value, not the marker.
    """

    (tmp_path / "unsanitised.json").write_text(json.dumps(_tool_call_transcript()), encoding="utf-8")

    report = fixture_privacy_scan.scan_fixture_tree(tmp_path)

    assert report["passed"] is False
    assert dict((finding["path"], finding["kinds"]) for finding in report["findings"])["unsanitised.json"] == [
        "operator_path",
        "unsanitised_environment_tag",
        "unsanitised_skill_inventory",
    ]

    sanitised, _ = sanitize_body(_tool_call_transcript())
    (tmp_path / "unsanitised.json").write_text(json.dumps(sanitised), encoding="utf-8")

    assert fixture_privacy_scan.scan_fixture_tree(tmp_path)["passed"] is True


# Absolute workspace roots that carry no ``<cwd>``/``### Available skills``
# marker and are not one of the four prefixes the path rule used to know
# (``/tmp``, ``/mnt``, ``/home/<user>``, ``/Users/<user>``). Every one of them
# is somebody's real checkout: ``/srv`` and ``/opt`` on a server, ``/root`` in
# ``docker run`` and in a devcontainer, ``/data`` and ``/u`` on shared boxes,
# ``/Volumes`` on macOS, and the Windows profile directory.
_OPERATOR_WORKSPACES = (
    "/srv/acme-holdings/project-bluebird",
    "/root/acme-internal-merger",
    "/opt/acme-holdings/ledger",
    "/data/clients/acme-holdings",
    "/u/jane/acme-holdings",
    "/Volumes/AcmeHoldings/ledger",
    "/home/사용자/프로젝트/비밀",
    "C:\\Users\\jane.doe\\acme-holdings",
)


def _workspace_leak_body(workspace: str) -> dict[str, Any]:
    """A tool call whose only operator marker is the absolute path itself.

    No environment tag and no skill inventory, so neither whole-file backstop
    kind can fire: the path is the entire evidence, exactly as it arrives in a
    second turn's ``function_call.arguments``.
    """

    return {
        "model": "gpt-5.5",
        "input": [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "shell",
                "arguments": json.dumps({"command": ["bash", "-lc", f"cd {workspace} && ls"]}),
            },
            {"type": "function_call_output", "call_id": "call_1", "output": f"{workspace}/README.md\n"},
        ],
    }


@pytest.mark.parametrize("workspace", _OPERATOR_WORKSPACES)
def test_an_operator_workspace_outside_the_home_vocabulary_is_rewritten(workspace: str) -> None:
    """The path rule is a shape, not a prefix vocabulary.

    A four-prefix list is a guess about where operators keep their work, and it
    was wrong for every root here. The rule now matches an absolute path by
    shape, so the sanitiser no longer depends on having guessed the operator's
    filesystem layout.
    """

    sanitised, redactions = sanitize_body(_workspace_leak_body(workspace))

    assert workspace not in json.dumps(sanitised), f"{workspace} survived sanitisation"
    assert [redaction.path for redaction in redactions] == ["input[0].arguments", "input[1].output"]
    assert PLACEHOLDERS.workspace in sanitised["input"][0]["arguments"]


@pytest.mark.parametrize("workspace", _OPERATOR_WORKSPACES)
def test_an_operator_workspace_outside_the_home_vocabulary_fails_the_privacy_gate(
    workspace: str, tmp_path: Path
) -> None:
    """The backstop half: marker-free text used to pass ``--strict`` as well.

    The two whole-file kinds are conditioned on a marker (an environment tag, a
    skill inventory heading). A bare workspace path carries neither, so the
    privacy gate is the *only* thing standing between a future capture and a
    committed operator path.
    """

    (tmp_path / "candidate.json").write_text(json.dumps(_workspace_leak_body(workspace)), encoding="utf-8")

    report = fixture_privacy_scan.scan_fixture_tree(tmp_path)

    assert report["passed"] is False, workspace
    assert dict((finding["path"], finding["kinds"]) for finding in report["findings"])["candidate.json"] == [
        "operator_path"
    ]


def test_a_relative_path_a_url_and_a_prose_slash_list_are_not_operator_paths() -> None:
    """The shape is anchored, so widening it did not make everything a path."""

    innocuous = (
        "See tests/unit/test_parser.py and r0/example-skill/SKILL.md, "
        "read https://example.com/docs/guide, pick cream/sand/tan, and try ../sibling/dir."
    )

    assert codex_body_sanitize.rewrite_operator_text(innocuous) == innocuous


def test_the_placeholder_namespace_is_not_rewritten_into_itself() -> None:
    """Idempotence: the sanitiser's own output must not match its own path rule.

    ``/workspace/skills`` is the skill-root placeholder; a rule that rewrote
    every absolute path would collapse it onto ``/workspace/repo`` on a second
    pass. A *different* ``/workspace`` directory is still the operator's, and is
    still rewritten.
    """

    keep = f"roots `{PLACEHOLDERS.skill_root}` and `{PLACEHOLDERS.workspace}`"

    assert codex_body_sanitize.rewrite_operator_text(keep) == keep
    assert PLACEHOLDERS.workspace in codex_body_sanitize.rewrite_operator_text("cd /workspace/acme-ledger")
    assert "acme-ledger" not in codex_body_sanitize.rewrite_operator_text("cd /workspace/acme-ledger")


@pytest.mark.parametrize(
    "name",
    [name for name, entry in gate.PROVENANCE.items() if not entry["carries_client_telemetry"]],
)
def test_sanitising_a_committed_fixture_again_changes_nothing(name: str) -> None:
    """Idempotence on the real corpus, not only on the synthetic body.

    The captured fixtures carry Codex's own ``/abs/path/app.py`` documentation
    placeholder in the base instructions; a path rule that rewrote it would
    silently rewrite every fixture the next time one was re-sanitised. The
    pre-strip fixtures are excluded because they exist *un*sanitised, to feed
    production's telemetry stripper.
    """

    body = json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    sanitised, redactions = sanitize_body(body)

    assert redactions == []
    assert json.dumps(sanitised, sort_keys=True) == json.dumps(body, sort_keys=True), name


def test_the_codex_agent_namespace_is_cleared_by_value_not_by_prefix(tmp_path: Path) -> None:
    """``/root/task1`` is ``spawn_agent`` vocabulary; ``/root/<repo>`` is a checkout.

    ``/root`` is the ``docker run`` and devcontainer default, so exempting the
    prefix would blind the gate to exactly the workspace a containerised capture
    leaks. The exemption is the whole path, and it is cleared in the sanitiser's
    predicate so both halves agree.
    """

    bundle = {
        "type": "additional_tools",
        "tools": [
            {
                "type": "namespace",
                "tools": [{"name": "spawn_agent", "description": "Task `/root/task1` spawns `/root/task1/task_3`."}],
            }
        ],
    }
    (tmp_path / "generated.json").write_text(json.dumps({"input": [bundle]}), encoding="utf-8")

    assert fixture_privacy_scan.scan_fixture_tree(tmp_path)["passed"] is True

    (tmp_path / "generated.json").write_text(
        json.dumps({"input": [{"type": "function_call", "arguments": "cd /root/acme-internal-merger && ls"}]}),
        encoding="utf-8",
    )

    assert fixture_privacy_scan.scan_fixture_tree(tmp_path)["passed"] is False


def test_the_gate_judges_the_byte_preserved_tool_declarations_too(tmp_path: Path) -> None:
    """The sanitiser cannot rewrite ``tools``; the gate is what covers it.

    A tool description is not always Codex's own text -- an MCP server the
    operator runs supplies its own -- and the sanitiser byte-preserves the array
    because it is the load-bearing portability evidence. A path that reaches it
    is therefore only ever caught here, and used to be caught nowhere: the
    reproduction committed the operator's workspace twice, once in the tool call
    and once in the declaration.
    """

    (tmp_path / "candidate.json").write_text(
        json.dumps(
            {
                "model": "gpt-5.5",
                "tools": [{"type": "function", "name": "ledger", "description": "Runs in /srv/acme-holdings/ledger."}],
            }
        ),
        encoding="utf-8",
    )

    report = fixture_privacy_scan.scan_fixture_tree(tmp_path)

    assert report["findings"] == [{"path": "candidate.json", "kinds": ["operator_path"]}]


def test_the_operator_path_backstop_still_judges_a_body_that_will_not_parse(tmp_path: Path) -> None:
    """The pass is over bytes, so a truncated capture is judged like any other."""

    (tmp_path / "truncated.json").write_text('{"input": [{"arguments": "cd /srv/acme/ledger', encoding="utf-8")

    report = fixture_privacy_scan.scan_fixture_tree(tmp_path)

    assert report["findings"] == [{"path": "truncated.json", "kinds": ["operator_path"]}]


def test_the_rewriter_is_a_no_op_on_text_without_operator_markers() -> None:
    innocuous = "Please refactor the parser and keep the public signature stable."

    assert codex_body_sanitize.rewrite_operator_text(innocuous) == innocuous


def test_sanitisation_is_idempotent() -> None:
    once, _ = sanitize_body(_realistic_body())
    twice, second_redactions = sanitize_body(once)

    assert json.dumps(twice, sort_keys=True) == json.dumps(once, sort_keys=True)
    assert second_redactions == []


def test_an_unreviewed_top_level_field_fails_closed() -> None:
    body = _realistic_body()
    body["x_future_codex_field"] = {"nested": True}

    with pytest.raises(UnsanitisableBodyError, match="x_future_codex_field"):
        sanitize_body(body)


def test_the_field_sets_are_closed_and_disjoint() -> None:
    assert ALLOWED_TOP_LEVEL_FIELDS == SANITISED_TOP_LEVEL_FIELDS | PRESERVED_TOP_LEVEL_FIELDS
    assert not DROPPED_TOP_LEVEL_FIELDS & SHAPE_PRESERVED_TOP_LEVEL_FIELDS
    assert not WEBSOCKET_ENVELOPE_FIELDS & SHAPE_PRESERVED_TOP_LEVEL_FIELDS
    # The envelope is not telemetry, so it stays out of the set that is pinned
    # against production's ``STRIPPED_TELEMETRY_FIELDS``.
    assert not WEBSOCKET_ENVELOPE_FIELDS & DROPPED_TOP_LEVEL_FIELDS
    assert PLACEHOLDERS.workspace == "/workspace/repo"
    assert is_placeholder_uuid(placeholder_uuid(0)) and not is_placeholder_uuid(_LIVE_SESSION)


def test_a_websocket_capture_sanitises_into_a_fixture() -> None:
    """The frame envelope goes; ``generate`` stays, because it is Codex-emitted evidence.

    A websocket capture is persisted verbatim -- the frame *is* the request body
    on that transport -- so without this the shipped lane produced a file its
    own sanitiser refused as an unreviewed top-level field.
    """

    body = _realistic_body() | {"type": "response.create", "generate": None}

    sanitised, redactions = sanitize_body(body)

    assert "type" not in sanitised
    assert sanitised["generate"] is None
    assert Redaction("type", "websocket_envelope_dropped") in redactions


# --- headers sidecar ------------------------------------------------------------------


def test_headers_drop_the_credential_and_the_whole_codex_identifier_family() -> None:
    headers = {
        "Authorization": "Bearer sk-live-abcdefghijklmnop",
        "chatgpt-account-id": "acct_0199f2c1",
        "session-id": _LIVE_SESSION,
        "thread-id": _LIVE_SESSION,
        "x-client-request-id": _LIVE_TURN,
        "x-codex-turn-metadata": json.dumps({"session_id": _LIVE_SESSION}),
        "originator": "codex_cli_rs",
        "user-agent": "codex_exec/0.154.0 (Linux 6.8.0; x86_64) tmux",
        "content-type": "application/json",
    }

    sanitised, redactions = sanitize_headers(headers)

    assert set(sanitised) == {"content-type", "user-agent"}
    assert sanitised["user-agent"] == "codex_exec/0.154.0"
    assert _LIVE_SESSION not in json.dumps(sanitised)
    assert {redaction.kind for redaction in redactions} == {"header_dropped", "user_agent_tail_dropped"}


# --- the planted mutations ------------------------------------------------------------


def _corpus(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """A writable copy of the committed corpus plus its parsed provenance."""

    root = tmp_path / "codex_bodies"
    shutil.copytree(FIXTURES, root)
    provenance = json.loads((root / gate.PROVENANCE_NAME).read_text(encoding="utf-8"))
    return root, provenance


def _run_gate(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    provenance: dict[str, Any],
) -> None:
    monkeypatch.setattr(gate, "FIXTURES", root)
    monkeypatch.setattr(gate, "PROVENANCE", provenance["fixtures"])
    monkeypatch.setattr(gate, "FIXTURE_NAMES", sorted(provenance["fixtures"]))
    (root / gate.PROVENANCE_NAME).write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")


def _scan(root: Path) -> dict[str, Any]:
    """The shipped default: the telemetry-key exemptions come from ``provenance.json``.

    No ``allow_telemetry_keys`` argument, so the mutations are judged by exactly
    the invocation the runbook documents.
    """

    return fixture_privacy_scan.scan_fixture_tree(root)


def test_mutation_readding_client_telemetry_fails_the_privacy_gate(tmp_path: Path) -> None:
    root, provenance = _corpus(tmp_path)
    body = json.loads((root / CAPTURED_STANDARD).read_text(encoding="utf-8"))
    body["client_metadata"] = {"session_id": _LIVE_SESSION}
    (root / CAPTURED_STANDARD).write_text(json.dumps(body), encoding="utf-8")

    report = _scan(root)

    assert report["passed"] is False
    kinds = {finding["path"]: finding["kinds"] for finding in report["findings"]}
    assert fixture_privacy_scan.TELEMETRY_KEY_KIND in kinds[CAPTURED_STANDARD]
    assert "identifier_key" in kinds[CAPTURED_STANDARD]


def test_mutation_a_live_cache_key_fails_the_privacy_gate(tmp_path: Path) -> None:
    root, provenance = _corpus(tmp_path)
    body = json.loads((root / CAPTURED_LITE).read_text(encoding="utf-8"))
    body["prompt_cache_key"] = _LIVE_SESSION
    (root / CAPTURED_LITE).write_text(json.dumps(body), encoding="utf-8")

    report = _scan(root)

    assert report["passed"] is False
    assert "uuid" in dict((finding["path"], finding["kinds"]) for finding in report["findings"])[CAPTURED_LITE]


def test_mutation_an_operator_home_path_fails_the_privacy_gate(tmp_path: Path) -> None:
    """The identifier pass exists because the credential scanner has no path vocabulary."""

    root, provenance = _corpus(tmp_path)
    body = json.loads((root / CAPTURED_STANDARD).read_text(encoding="utf-8"))
    body["instructions"] = f"Working in /home/{getpass.getuser()}/work/codex-lb on the parser."
    (root / CAPTURED_STANDARD).write_text(json.dumps(body), encoding="utf-8")

    report = _scan(root)

    assert report["passed"] is False
    kinds = dict((finding["path"], finding["kinds"]) for finding in report["findings"])[CAPTURED_STANDARD]
    assert "operator_path" in kinds
    # The unmutated corpus passes the same scan, so the finding is the mutation's.
    assert _scan(_corpus(tmp_path / "pristine")[0])["passed"] is True


def test_mutation_a_skill_inventory_inside_a_tool_call_fails_the_privacy_gate(tmp_path: Path) -> None:
    """Planted on the real corpus, in the item shape the field walk used to miss."""

    root, _provenance = _corpus(tmp_path)
    body = json.loads((root / CAPTURED_STANDARD).read_text(encoding="utf-8"))
    body["input"].append({"type": "function_call_output", "call_id": "call_1", "output": _TOOL_CALL_LEAK})
    (root / CAPTURED_STANDARD).write_text(json.dumps(body), encoding="utf-8")

    report = _scan(root)

    assert report["passed"] is False
    kinds = dict((finding["path"], finding["kinds"]) for finding in report["findings"])[CAPTURED_STANDARD]
    assert kinds == ["operator_path", "unsanitised_environment_tag", "unsanitised_skill_inventory"]
    # The unmutated corpus passes the same scan, so the finding is the mutation's.
    assert _scan(_corpus(tmp_path / "pristine")[0])["passed"] is True


def test_mutation_a_credential_shape_fails_through_the_reused_scanner(tmp_path: Path) -> None:
    """Reuse, not reimplementation: the finding comes from ``privacy_scan``'s own patterns."""

    root, provenance = _corpus(tmp_path)
    body = json.loads((root / CAPTURED_STANDARD).read_text(encoding="utf-8"))
    body["instructions"] = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP"
    (root / CAPTURED_STANDARD).write_text(json.dumps(body), encoding="utf-8")

    report = _scan(root)

    assert report["passed"] is False
    kinds = dict((finding["path"], finding["kinds"]) for finding in report["findings"])[CAPTURED_STANDARD]
    assert {"bearer_token", "jwt"} <= set(kinds)


def test_mutation_removing_every_tool_surface_fails_the_shape_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, provenance = _corpus(tmp_path)
    body = json.loads((root / CAPTURED_STANDARD).read_text(encoding="utf-8"))
    del body["tools"]
    (root / CAPTURED_STANDARD).write_text(json.dumps(body), encoding="utf-8")
    _run_gate(monkeypatch, root, provenance)

    with pytest.raises(AssertionError, match=r"captured_gpt55_standard_http\.json \[captured, slug=gpt-5\.5"):
        gate.test_every_fixture_is_shaped_like_a_codex_responses_body(CAPTURED_STANDARD)


def test_mutation_flipping_an_origin_without_the_readme_fails_the_sync_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, provenance = _corpus(tmp_path)
    provenance["fixtures"][SYNTHETIC_STANDARD]["origin"] = "captured"
    _run_gate(monkeypatch, root, provenance)

    with pytest.raises(AssertionError, match="README says synthetic"):
        gate.test_readme_rows_and_provenance_rows_agree_in_both_directions()


def test_mutation_a_wrong_recorded_reason_fails_the_verdict_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proves the recorded verdict is really asserted, not merely stored."""

    root, provenance = _corpus(tmp_path)
    provenance["fixtures"][CAPTURED_STANDARD]["expected_portability_verdict"]["reason"] = "not_portable_history"
    _run_gate(monkeypatch, root, provenance)

    with pytest.raises(AssertionError, match="not_portable_tools"):
        gate.test_every_fixture_matches_its_recorded_view_and_verdict(CAPTURED_STANDARD)


def test_mutation_an_undeclared_extra_file_fails_the_sync_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, provenance = _corpus(tmp_path)
    shutil.copyfile(root / CAPTURED_STANDARD, root / "undeclared_capture.json")
    _run_gate(monkeypatch, root, provenance)

    with pytest.raises(AssertionError):
        gate.test_files_on_disk_and_provenance_rows_agree_in_both_directions()
