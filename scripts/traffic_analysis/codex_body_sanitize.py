"""Sanitise a captured Codex Responses request body into a committable fixture.

Pure functions plus a thin CLI. Imports nothing from ``app``: the fixture gate
(``tests/unit/test_codex_body_fixtures.py``) is where this module's field sets
are pinned against the production constants, so the tooling stays runnable on a
checkout without the application environment.

Three rules, in tension, decided in this order:

1. **Fail closed on an unrecognised top-level field.** A positive allowlist,
   not a scan for known telemetry, so a future Codex field can never be
   committed unreviewed.
2. **Preserve absence.** A real Responses-Lite body carries no ``instructions``,
   no ``tools`` and no ``stream_options``; a real gpt-5.5 body carries no
   ``stream_options`` and no ``reasoning.summary``. The overflow portability
   view declines unknown top-level fields, so fabricating a key would change
   the recorded verdict. Nothing here ever adds a key.
3. **Redact operator data, keep evidence.** Telemetry fields go whole; paths,
   dates, the skill inventory and identifiers become fixed placeholders. Every
   text-bearing field of an input item is rewritten, not only a message's
   ``content``: a ``function_call``'s ``arguments`` and a
   ``function_call_output``'s ``output`` carry the operator's commands and their
   output.
   Input-item ``id`` values are *replaced*, not removed, by default: a
   non-empty prefixed id is what makes a native Codex body decline as
   ``not_portable_history``, and deleting it would hide that fact from the
   fixture corpus. Pass ``strip_item_ids=True`` for the stripped variant.

``tools`` is byte-preserved: it is Codex-generated, carries no operator data,
and is the load-bearing evidence for the tool-declaration portability gaps.

A websocket capture is persisted verbatim, so it arrives with the transport's
frame envelope (``type``) around the Responses body. That envelope is removed
here -- it is not a Responses field -- while ``generate``, which the frame does
carry as a Responses field, is preserved like any other Codex-emitted value.
"""

from __future__ import annotations

import argparse
import copy
import getpass
import re
import socket
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from scripts.traffic_analysis.artifacts import atomic_write_json, read_json
except ModuleNotFoundError:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.traffic_analysis.artifacts import atomic_write_json, read_json


class UnsanitisableBodyError(ValueError):
    """A captured body carries a field this sanitiser has never reviewed."""


@dataclass(frozen=True, slots=True)
class Placeholders:
    """Fixed substitutes. Never derived from the capture, so output is stable."""

    workspace: str = "/workspace/repo"
    skill_root: str = "/workspace/skills"
    skill_name: str = "example-skill"
    skill_description: str = "Placeholder skill entry for the fixture corpus."
    date: str = "2026-01-01"
    timezone: str = "Etc/UTC"
    shell: str = "bash"
    account: str = "codex-fixture"
    # Namespace for every placeholder UUID: a RFC 4122 v4 layout whose node
    # field is a zero-padded ordinal, so ``is_placeholder_uuid`` recognises the
    # whole family without the scanner importing a literal list.
    uuid_prefix: str = "00000000-0000-4000-8000-"


PLACEHOLDERS = Placeholders()

_PLACEHOLDER_UUID_PATTERN = re.compile(r"\A00000000-0000-4000-8000-\d{12}\Z")

# Whole top-level fields the fixture never keeps. A superset of production's
# ``STRIPPED_TELEMETRY_FIELDS`` (pinned in the fixture gate).
DROPPED_TOP_LEVEL_FIELDS: frozenset[str] = frozenset({"client_metadata", "access_programs"})

# The websocket lane's frame envelope, not a Responses field: production adds
# the same ``type`` in ``_build_websocket_response_create_payload``. The capture
# persists the frame verbatim (it *is* the request body on that transport), so
# the envelope is removed here rather than by rewriting captured bytes. Kept out
# of ``DROPPED_TOP_LEVEL_FIELDS`` because that set is pinned against
# production's telemetry stripper and this is not telemetry.
WEBSOCKET_ENVELOPE_FIELDS: frozenset[str] = frozenset({"type"})

# Replaced by a fixed placeholder. ``prompt_cache_key`` *equals the session id*
# in a real body, so a "cache key" is a session identifier by another name.
PLACEHOLDER_TOP_LEVEL_FIELDS: frozenset[str] = frozenset({"prompt_cache_key"})

# Removed from ``stream_options``; the object is dropped once emptied, exactly
# as production's ``strip_source_telemetry`` does.
SANITISED_STREAM_OPTIONS_KEYS: frozenset[str] = frozenset({"reasoning_summary_delivery"})
STREAM_OPTIONS_FIELD = "stream_options"

# Structure survives, operator strings inside do not.
TEXT_REWRITTEN_TOP_LEVEL_FIELDS: frozenset[str] = frozenset({"instructions", "input"})

# Forwarded byte for byte.
PRESERVED_TOP_LEVEL_FIELDS: frozenset[str] = frozenset(
    {
        "model",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "text",
        "include",
        "store",
        "stream",
        "truncation",
        "max_output_tokens",
        "temperature",
        "top_p",
        "metadata",
        "user",
        "safety_identifier",
        "prompt_cache_retention",
        "previous_response_id",
        "conversation",
        "prompt",
        "service_tier",
        # Codex-emitted, and the load-bearing evidence that a websocket body is
        # shaped differently: the turn frame carries ``generate: null`` (the
        # prewarm frame carries ``false``). Preserved rather than dropped, so a
        # websocket fixture would record the real ``not_portable_unknown_field``
        # consequence instead of hiding it.
        "generate",
    }
)

SANITISED_TOP_LEVEL_FIELDS: frozenset[str] = (
    DROPPED_TOP_LEVEL_FIELDS
    | PLACEHOLDER_TOP_LEVEL_FIELDS
    | TEXT_REWRITTEN_TOP_LEVEL_FIELDS
    | WEBSOCKET_ENVELOPE_FIELDS
    | {STREAM_OPTIONS_FIELD}
)

# Never dropped and never fabricated: the field's shape reaches the fixture.
SHAPE_PRESERVED_TOP_LEVEL_FIELDS: frozenset[str] = PRESERVED_TOP_LEVEL_FIELDS | TEXT_REWRITTEN_TOP_LEVEL_FIELDS

ALLOWED_TOP_LEVEL_FIELDS: frozenset[str] = SANITISED_TOP_LEVEL_FIELDS | PRESERVED_TOP_LEVEL_FIELDS

# Header names a sidecar never keeps. ``x-codex-turn-metadata`` is a JSON string
# embedding installation/session/thread/window/turn identifiers, so the whole
# ``x-codex-*`` family goes by prefix rather than by name.
DROPPED_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "chatgpt-account-id",
        "originator",
        "session-id",
        "thread-id",
        "x-client-request-id",
    }
)
DROPPED_HEADER_PREFIXES: tuple[str, ...] = ("x-codex-",)
USER_AGENT_HEADER = "user-agent"

# Identifier keys a nested object may carry. ``turn_id`` inside
# ``internal_chat_message_metadata_passthrough`` is account-neutral to
# production's replay predicate but is still a live identifier on the wire.
PLACEHOLDER_NESTED_IDENTIFIER_KEYS: frozenset[str] = frozenset({"turn_id"})
_INTERNAL_CHAT_METADATA_FIELD = "internal_chat_message_metadata_passthrough"


@dataclass(frozen=True, slots=True)
class Redaction:
    """What changed and where. Never carries the removed value."""

    path: str
    kind: str


_SKILL_ROOT_ENTRY = re.compile(r"(?m)^(-\s+`[^`]+`\s*=\s*`)([^`]*)(`)$")
_SKILL_INVENTORY = re.compile(r"(?s)(### Available skills\n)(.*?)(?=\n#{1,3} |\n</skills_instructions>|\Z)")
ENVIRONMENT_TAGS: tuple[tuple[str, str], ...] = (
    ("cwd", "workspace"),
    ("root", "workspace"),
    ("current_date", "date"),
    ("timezone", "timezone"),
    ("shell", "shell"),
)
_AGENTS_HEADING = re.compile(r"(?m)^(#\s+AGENTS\.md instructions for\s+)(\S.*)$")

# An absolute filesystem path, matched as a *shape* rather than as a prefix
# vocabulary. The four prefixes this replaced (``/tmp``, ``/mnt``,
# ``/home/<user>``, ``/Users/<user>``) were a guess about where operators keep
# their work, and the guess was wrong for ``/srv``, ``/opt``, ``/data``, ``/u``,
# ``/Volumes``, the Windows profile directory and ``/root/<repo>`` -- the
# devcontainer and ``docker run`` default. A path outside the guess reached the
# fixture *and* passed the privacy gate whenever it carried no environment tag
# and no skill inventory to trip the whole-file backstop.
#
# Anchored on both ends so widening the vocabulary does not make everything a
# path: two or more segments, and never preceded by a word character, ``/``,
# ``:``, ``.`` or ``\``. That leaves a relative path (``tests/unit/x.py``), a
# URL (``https://example.com/a/b``), a prose enumeration (``cream/sand/tan``)
# and a ``../sibling`` reference unmatched. A segment is any run of characters
# that is not a separator, a text delimiter or a backslash, so a non-ASCII path
# (``/home/사용자/프로젝트``) matches like any other while a regex literal
# (``/\r?\n/``) and a JSON-escaped newline do not. ``\uXXXX`` is admitted
# because the realistic carrier is a ``function_call``'s ``arguments``, which is
# itself a JSON string and may arrive escaped.
_PATH_SEGMENT = r"(?:[^\s\"'`<>,;:)\]}/\\]|\\u[0-9a-fA-F]{4})+"
_WINDOWS_SEPARATOR = r"[\\/]{1,2}"
OPERATOR_PATH: re.Pattern[str] = re.compile(
    rf"(?<![A-Za-z0-9_/:.\\])(?:"
    rf"[A-Za-z]:{_WINDOWS_SEPARATOR}{_PATH_SEGMENT}(?:{_WINDOWS_SEPARATOR}{_PATH_SEGMENT})*"
    rf"|/{_PATH_SEGMENT}(?:/{_PATH_SEGMENT})+)"
)

# Absolute paths that name no operator, so neither the sanitiser nor the gate
# acts on them. Both entries are measured against the committed corpus rather
# than imagined, and both are matched against the whole path:
#
# * ``/abs/path/…``, the literal documentation placeholder Codex's own base
#   instructions use for "an absolute path" (``e.g. /abs/path/app.py``);
# * ``/root/taskN[/task_M]``, the agent-task namespace Codex's own
#   ``spawn_agent`` description documents in the Lite tool bundle. The prefix is
#   *not* exempt: ``/root/<repo>`` is where ``docker run`` and devcontainers keep
#   the operator's checkout.
#
# Adding an entry is the only way a Codex vocabulary path stays out of the
# findings, so the failure mode of a missing one is a red gate on a fresh
# capture -- never a committed leak.
_CODEX_VOCABULARY_PATH = re.compile(r"\A(?:/abs/path/|/root/task[0-9]+(?:/task_[0-9]+)*\Z)")
# Content-part fields that carry operator text (``input_text``, ``output_text``).
_TEXT_PART_FIELDS: tuple[str, ...] = ("text",)

# Input-item fields that carry operator text, each as a string or as a list of
# parts. ``content`` is the message form; ``arguments`` is the call a
# ``function_call`` made, ``output`` is what a ``function_call_output`` printed,
# ``input`` is the ``custom_tool_call`` form of ``arguments`` and ``summary`` is
# the reasoning summary. Deliberately not here: ``tools`` (the Lite
# ``additional_tools`` bundle), which is Codex-generated and byte preserved.
TEXT_BEARING_ITEM_FIELDS: tuple[str, ...] = ("content", "arguments", "input", "output", "summary")


_MINIMUM_IDENTITY_LENGTH = 4

# Host and account names this pass will not act on: they identify no operator,
# and rewriting them would corrupt genuine content.
#
# The first group is the same string on every machine of its class -- container
# and cloud-image defaults, CI runner accounts, system accounts. The second is
# vocabulary Codex's own payload uses, measured against the committed corpus.
# Both were reachable, not hypothetical: with ``getpass.getuser()`` returning
# ``root`` (the default in ``docker run``, in devcontainers, in many self-hosted
# runner images and under ``sudo pytest``) the identity pass matched
# ``<special>:root</special>`` and Codex's ``spawn_agent`` description in both
# captured fixtures, so the privacy gate reported a ``live_identity`` finding
# that no operator could clear -- while the sanitiser rewrote ``\broot\b`` inside
# ``<environment_context>`` and destroyed the evidence the design keeps. Of 33
# plausible host/account names tried, 24 hit at least one committed fixture.
GENERIC_IDENTITY_NAMES: frozenset[str] = frozenset(
    {
        # Defaults and system accounts.
        "admin",
        "administrator",
        "alpine",
        "builder",
        "centos",
        "codespace",
        "container",
        "daemon",
        "debian",
        "devcontainer",
        "docker",
        "fedora",
        "guest",
        "jenkins",
        "localhost",
        "nobody",
        "root",
        "runner",
        "ubuntu",
        "user",
        "users",
        "vagrant",
        # Codex payload vocabulary.
        "agent",
        "auto",
        "bash",
        "build",
        "codex",
        "custom",
        "function",
        "high",
        "input",
        "local",
        "main",
        "medium",
        "model",
        "name",
        "shell",
        "store",
        "stream",
        "test",
        "text",
        "tools",
        "type",
        "work",
    }
)


def identity_candidates(hostname: str, username: str) -> tuple[str, ...]:
    """The identity strings worth rewriting, longest first then alphabetical.

    Deterministic on purpose: the replacement order is part of the sanitiser's
    output, and iterating a set made ties depend on hash order.
    """

    candidates = {hostname, username}
    return tuple(
        sorted(
            (
                name
                for name in candidates
                if len(name) >= _MINIMUM_IDENTITY_LENGTH and name.casefold() not in GENERIC_IDENTITY_NAMES
            ),
            key=lambda name: (-len(name), name),
        )
    )


def live_identity_strings() -> tuple[str, ...]:
    """The running host and account names, minus the ones that name no operator.

    Only caught for the machine that runs the sanitiser (and the scanner): the
    same value from another operator's host is invisible here. That, and
    ``GENERIC_IDENTITY_NAMES``, are the documented limits of this pass rather
    than a claim of completeness.
    """

    return identity_candidates(socket.gethostname(), getpass.getuser())


def names_an_operator_location(path: str, placeholders: Placeholders = PLACEHOLDERS) -> bool:
    """Whether an absolute path found by ``OPERATOR_PATH`` is the operator's.

    The single predicate both this module and ``fixture_privacy_scan`` use, so
    the sanitiser rewrites exactly what the privacy gate flags. The placeholder
    namespace is compared by exact value, not by prefix: a second sanitiser pass
    must be a no-op, while ``/workspace/<repo>`` -- a real devcontainer checkout
    -- is still the operator's.
    """

    return path not in {placeholders.workspace, placeholders.skill_root} and not _CODEX_VOCABULARY_PATH.match(path)


def is_placeholder_uuid(value: str) -> bool:
    """Whether ``value`` belongs to the fixture's placeholder UUID family."""

    return bool(_PLACEHOLDER_UUID_PATTERN.match(value))


def placeholder_uuid(ordinal: int, placeholders: Placeholders = PLACEHOLDERS) -> str:
    return f"{placeholders.uuid_prefix}{ordinal:012d}"


def _rewrite_skills_instructions(text: str, placeholders: Placeholders) -> str:
    text = _SKILL_ROOT_ENTRY.sub(lambda m: f"{m.group(1)}{placeholders.skill_root}{m.group(3)}", text)
    inventory = (
        f"- {placeholders.skill_name}: {placeholders.skill_description} (file: r0/{placeholders.skill_name}/SKILL.md)"
    )
    return _SKILL_INVENTORY.sub(lambda m: f"{m.group(1)}{inventory}", text)


def rewrite_operator_text(text: str, placeholders: Placeholders = PLACEHOLDERS) -> str:
    """Replace every operator-identifying string in one text value.

    A no-op on text that carries none of the markers, which is what lets the
    fixture gate assert byte preservation for the fields that matter.
    """

    if "<skills_instructions>" in text or "### Skill roots" in text:
        text = _rewrite_skills_instructions(text, placeholders)
    for tag, attribute in ENVIRONMENT_TAGS:
        # Every replacement goes through a callable: a template string would
        # interpret backslashes and group references in the placeholder, and
        # escaping it for a *pattern* instead writes the escapes into the
        # output (``2026\-01\-01``).
        replacement = getattr(placeholders, attribute)
        text = re.sub(
            rf"(<{tag}>)[^<]*(</{tag}>)",
            lambda match, value=replacement: f"{match.group(1)}{value}{match.group(2)}",
            text,
        )
    text = _AGENTS_HEADING.sub(lambda m: f"{m.group(1)}{placeholders.workspace}", text)
    text = OPERATOR_PATH.sub(
        lambda match: (
            placeholders.workspace if names_an_operator_location(match.group(), placeholders) else match.group()
        ),
        text,
    )
    for identity in live_identity_strings():
        text = re.sub(rf"\b{re.escape(identity)}\b", lambda _: placeholders.account, text)
    return text


def _rewritten(value: str, path: str, placeholders: Placeholders, redactions: list[Redaction]) -> str:
    rewritten = rewrite_operator_text(value, placeholders)
    if rewritten != value:
        redactions.append(Redaction(path, "operator_text"))
    return rewritten


def _rewrite_item_text(
    item: dict[str, Any],
    path: str,
    placeholders: Placeholders,
    redactions: list[Redaction],
) -> None:
    """Rewrite the operator text in one input item's text-bearing fields, in place.

    Every field in ``TEXT_BEARING_ITEM_FIELDS``, not only ``content``. A
    transcript item is not always a message: a ``function_call`` carries the
    command the agent ran in ``arguments`` and a ``function_call_output`` carries
    what it printed in ``output`` (a string, or a list of parts). Both are as
    operator-specific as anything in a message, and walking only ``content`` let
    a cwd, a skill inventory and a skill-root path through the sanitiser *and*
    through ``fixture_privacy_scan --strict``, which had no vocabulary for them.

    Still not a walk of every nested string. The Lite ``additional_tools``
    bundle lives in the item's ``tools`` array and the tool declarations live in
    the top-level ``tools``; both are Codex-generated, both are the load-bearing
    evidence for the ``not_portable_lite_namespace`` verdict, and both stay byte
    identical. That scoping is what lets the path rule be a general shape:
    Codex's own ``spawn_agent`` description embeds ``/root/<task>`` agent
    namespaces, and the walk never reaches them, so rewriting ``/root/<repo>``
    in a transcript corrupts nothing. ``fixture_privacy_scan`` exempts the same
    regions for the same reason.
    """

    for field in TEXT_BEARING_ITEM_FIELDS:
        value = item.get(field)
        if isinstance(value, str):
            item[field] = _rewritten(value, f"{path}.{field}", placeholders, redactions)
            continue
        if not isinstance(value, list):
            continue
        for index, part in enumerate(value):
            if isinstance(part, str):
                value[index] = _rewritten(part, f"{path}.{field}[{index}]", placeholders, redactions)
                continue
            if not isinstance(part, dict):
                continue
            for part_field in _TEXT_PART_FIELDS:
                if isinstance(part.get(part_field), str):
                    part[part_field] = _rewritten(
                        part[part_field], f"{path}.{field}[{index}].{part_field}", placeholders, redactions
                    )


def _sanitise_item_identifiers(
    item: dict[str, Any],
    path: str,
    ordinal: int,
    placeholders: Placeholders,
    redactions: list[Redaction],
    *,
    strip_item_ids: bool,
) -> None:
    identifier = item.get("id")
    if isinstance(identifier, str) and identifier:
        if strip_item_ids:
            del item["id"]
            redactions.append(Redaction(f"{path}.id", "item_id_stripped"))
        else:
            prefix, separator, suffix = identifier.rpartition("_")
            replacement = f"{prefix}{separator}{placeholder_uuid(ordinal, placeholders)}" if separator else identifier
            if separator and not is_placeholder_uuid(suffix):
                item["id"] = replacement
                redactions.append(Redaction(f"{path}.id", "item_id_placeholder"))
    metadata = item.get(_INTERNAL_CHAT_METADATA_FIELD)
    if not isinstance(metadata, dict):
        return
    for key in sorted(PLACEHOLDER_NESTED_IDENTIFIER_KEYS & set(metadata)):
        if isinstance(metadata[key], str) and not is_placeholder_uuid(metadata[key]):
            metadata[key] = placeholder_uuid(ordinal, placeholders)
            redactions.append(Redaction(f"{path}.{_INTERNAL_CHAT_METADATA_FIELD}.{key}", "identifier_placeholder"))


def sanitize_body(
    body: dict[str, Any],
    *,
    placeholders: Placeholders = PLACEHOLDERS,
    strip_item_ids: bool = False,
) -> tuple[dict[str, Any], list[Redaction]]:
    """Return a committable copy of ``body`` plus the redaction log.

    Raises ``UnsanitisableBodyError`` for a top-level field outside
    ``ALLOWED_TOP_LEVEL_FIELDS``: an unreviewed field is never forwarded.
    """

    unknown = sorted(set(body) - ALLOWED_TOP_LEVEL_FIELDS)
    if unknown:
        raise UnsanitisableBodyError(f"unreviewed top-level field(s): {', '.join(unknown)}")
    sanitised = copy.deepcopy(body)
    redactions: list[Redaction] = []

    for field in sorted(DROPPED_TOP_LEVEL_FIELDS & set(sanitised)):
        del sanitised[field]
        redactions.append(Redaction(field, "telemetry_field_dropped"))

    for field in sorted(WEBSOCKET_ENVELOPE_FIELDS & set(sanitised)):
        del sanitised[field]
        redactions.append(Redaction(field, "websocket_envelope_dropped"))

    for field in sorted(PLACEHOLDER_TOP_LEVEL_FIELDS & set(sanitised)):
        if isinstance(sanitised[field], str) and not is_placeholder_uuid(sanitised[field]):
            sanitised[field] = placeholder_uuid(0, placeholders)
            redactions.append(Redaction(field, "identifier_placeholder"))

    stream_options = sanitised.get(STREAM_OPTIONS_FIELD)
    if isinstance(stream_options, dict):
        removed = False
        for key in sorted(SANITISED_STREAM_OPTIONS_KEYS & set(stream_options)):
            del stream_options[key]
            removed = True
            redactions.append(Redaction(f"{STREAM_OPTIONS_FIELD}.{key}", "telemetry_field_dropped"))
        if removed and not stream_options:
            del sanitised[STREAM_OPTIONS_FIELD]

    if isinstance(sanitised.get("instructions"), str):
        sanitised["instructions"] = _rewritten(sanitised["instructions"], "instructions", placeholders, redactions)

    input_items = sanitised.get("input")
    if isinstance(input_items, list):
        for index, item in enumerate(input_items):
            if not isinstance(item, dict):
                continue
            path = f"input[{index}]"
            _sanitise_item_identifiers(
                item,
                path,
                index + 1,
                placeholders,
                redactions,
                strip_item_ids=strip_item_ids,
            )
            _rewrite_item_text(item, path, placeholders, redactions)
    elif isinstance(input_items, str):
        sanitised["input"] = _rewritten(input_items, "input", placeholders, redactions)
    return sanitised, redactions


def sanitize_headers(headers: dict[str, str]) -> tuple[dict[str, str], list[Redaction]]:
    """Drop credential and identifier headers; keep the ``user-agent`` version only.

    The sidecar is an operator aid for reviewing a capture. It is never
    committed: even a disposable token leaves an ``authorization`` line shape in
    the raw file, and the fixture corpus reads bodies only.
    """

    sanitised: dict[str, str] = {}
    redactions: list[Redaction] = []
    for name in sorted(headers):
        lowered = name.casefold()
        if lowered in DROPPED_HEADERS or lowered.startswith(DROPPED_HEADER_PREFIXES):
            redactions.append(Redaction(lowered, "header_dropped"))
            continue
        if lowered == USER_AGENT_HEADER:
            # ``codex_cli_rs/0.154.0 (Ubuntu 24.04; x86_64) tmux`` -> the version only.
            leading = headers[name].split(" ", 1)[0]
            if leading != headers[name]:
                redactions.append(Redaction(lowered, "user_agent_tail_dropped"))
            sanitised[lowered] = leading
            continue
        sanitised[lowered] = headers[name]
    return sanitised, redactions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sanitise a captured Codex request body into a fixture.")
    parser.add_argument("--in", dest="source", type=Path, required=True, help="Captured body JSON")
    parser.add_argument("--out", dest="destination", type=Path, required=True, help="Sanitised fixture JSON")
    parser.add_argument("--headers-in", type=Path, help="Captured headers sidecar (reviewed, never committed)")
    parser.add_argument("--headers-out", type=Path, help="Sanitised headers sidecar")
    parser.add_argument("--strip-item-ids", action="store_true", help="Remove input-item ids instead of replacing them")
    parser.add_argument("--emit-redactions", type=Path, help="Write the redaction log as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    body = read_json(args.source)
    if not isinstance(body, dict):
        print(f"Captured body must be a JSON object: {args.source}", file=sys.stderr)
        return 2
    try:
        sanitised, redactions = sanitize_body(body, strip_item_ids=args.strip_item_ids)
    except UnsanitisableBodyError as exc:
        print(f"Refusing to sanitise {args.source}: {exc}", file=sys.stderr)
        return 2
    atomic_write_json(args.destination, sanitised)
    if args.headers_in and args.headers_out:
        raw_headers = read_json(args.headers_in)
        if isinstance(raw_headers, dict):
            sanitised_headers, header_redactions = sanitize_headers(raw_headers)
            atomic_write_json(args.headers_out, sanitised_headers)
            redactions.extend(header_redactions)
    kinds = sorted({redaction.kind for redaction in redactions})
    if args.emit_redactions:
        atomic_write_json(
            args.emit_redactions,
            {
                "schema_version": 1,
                "source": str(args.source),
                "strip_item_ids": args.strip_item_ids,
                "redactions": [{"path": item.path, "kind": item.kind} for item in redactions],
            },
        )
    print(f"Sanitised {args.source} -> {args.destination}: {len(redactions)} redaction(s), kinds={kinds}")
    print("Next: fixture_privacy_scan.py --root <dir> --strict, then add a provenance.json entry and a README row.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
