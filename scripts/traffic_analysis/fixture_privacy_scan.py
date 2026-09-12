"""Privacy gate for the committed Codex body fixtures.

Two passes over the same tree:

* **Credentials** -- ``privacy_scan.scan_tree`` unchanged, over every file. It
  already knows the shapes that must never be committed anywhere (token, API
  key, JWT, OAuth token fields).
* **Identifiers** -- this module, over the fixture bodies only (``*.json``).
  The credential scanner has no vocabulary for a workspace path, a live UUID or
  a telemetry key, and it *passes* the fixture tree today despite both fixtures
  carrying UUIDs and absolute paths.
* **Unsanitised operator text** -- the backstop for the sanitiser's field walk.
  The walk visits the fields of an input item it knows about, so an operator
  marker in a shape it has not met yet reaches the fixture; an environment tag
  or a skill inventory whose value is not the sanitiser's placeholder is caught
  here instead, anywhere in the file at any depth. Measured, not hypothetical: a
  ``<timezone>`` and a private skill inventory inside a
  ``function_call_output.output`` passed the sanitiser and ``--strict`` both.
* **Operator paths** -- the same backstop for text that carries no marker at
  all. Both marker kinds above are conditioned on a tag or a heading, so a bare
  ``cd /srv/acme/ledger`` in a tool call's arguments tripped neither, and the
  path kind only knew ``/home``, ``/Users``, ``/tmp`` and ``/mnt``. It now
  judges an absolute path by shape, through the sanitiser's own
  ``OPERATOR_PATH`` and ``names_an_operator_location``, so the two cannot
  disagree about what an operator path is.

The identifier pass deliberately skips ``*.md``: the corpus README has to be
able to name the keys the sanitiser removes, and prose is reviewed by a human,
not by shape. Credential shapes are still rejected in every file including the
README.

Every pattern is a *shape*, matched against the telemetry form rather than the
bare word, because the real Codex tool schema declares a legitimate numeric
``session_id`` parameter (the unified-exec session) -- a bare-word match would
red-line a genuine capture for the wrong reason. Findings never echo the
offending value.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

try:
    from scripts.traffic_analysis.artifacts import atomic_write_json
    from scripts.traffic_analysis.codex_body_sanitize import (
        ENVIRONMENT_TAGS,
        OPERATOR_PATH,
        PLACEHOLDERS,
        is_placeholder_uuid,
        live_identity_strings,
        names_an_operator_location,
    )
    from scripts.traffic_analysis.privacy_scan import scan_tree
except ModuleNotFoundError:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.traffic_analysis.artifacts import atomic_write_json
    from scripts.traffic_analysis.codex_body_sanitize import (
        ENVIRONMENT_TAGS,
        OPERATOR_PATH,
        PLACEHOLDERS,
        is_placeholder_uuid,
        live_identity_strings,
        names_an_operator_location,
    )
    from scripts.traffic_analysis.privacy_scan import scan_tree

_CHUNK_BYTES = 1024 * 1024
_OVERLAP_BYTES = 512

IDENTIFIER_SCAN_SUFFIXES: frozenset[str] = frozenset({".json"})

_UUID = re.compile(rb"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

# Telemetry keys that carry a *string* identifier. ``"session_id": {`` (a tool
# parameter schema) and ``session_id?: number`` (prose in a tool description)
# are both legitimate Codex tool vocabulary and must not match, which is why
# the pattern requires a quoted value -- and why a placeholder value is fine.
_STRING_VALUED_IDENTIFIER_KEYS: tuple[str, ...] = (
    "installation_id",
    "root_turn_id",
    "session_id",
    "thread_id",
    "turn_id",
    "window_id",
)

# Bare telemetry key names. Unlike every other kind this one cannot be
# conditioned on the value, so a fixture that exists to exercise the production
# telemetry stripper declares itself in ``provenance.json`` and is exempted by
# name rather than being made unrepresentative. The declaration is *read* from
# ``provenance.json`` (see ``declared_telemetry_key_bodies``) instead of being
# retyped on the command line: the documented gate step has to pass on a
# pristine checkout, and it previously needed three undocumented
# ``--allow-telemetry-keys`` values that existed only inside the unit tests.
TELEMETRY_KEY_KIND = "telemetry_field"

PROVENANCE_NAME = "provenance.json"


def _unsanitised_environment_tag_pattern() -> re.Pattern[bytes]:
    """``<cwd>``/``<timezone>``/… carrying anything but the sanitiser's placeholder.

    A shape, like every other kind here: the sanitised corpus keeps the tags (the
    fixture must stay a real Codex body) and the finding is the *value*. Built
    from the sanitiser's own table so the two cannot drift.
    """

    alternatives = []
    for tag, attribute in ENVIRONMENT_TAGS:
        opening = re.escape(f"<{tag}>".encode())
        placeholder = re.escape(f"{getattr(PLACEHOLDERS, attribute)}</{tag}>".encode())
        alternatives.append(opening + rb"(?!" + placeholder + rb")")
    return re.compile(rb"|".join(alternatives))


def _unsanitised_skill_inventory_pattern() -> re.Pattern[bytes]:
    """The operator's installed skill names and skill-root paths, unreplaced.

    The largest real leak in a captured body and the one no credential scanner
    has vocabulary for. Both forms are matched against the JSON escaping the
    bodies are stored in (``\\n``) as well as a literal newline.
    """

    newline = rb"(?:\\n|\n)"
    inventory = rb"### Available skills" + newline + rb"(?!- " + re.escape(PLACEHOLDERS.skill_name.encode()) + rb")"
    root_entry = newline + rb"- `[^`]{1,80}` *= *`(?!" + re.escape(PLACEHOLDERS.skill_root.encode()) + rb"`)"
    return re.compile(inventory + rb"|" + root_entry)


_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "identifier_key",
        re.compile(
            rb'"(?:'
            + rb"|".join(key.encode() for key in _STRING_VALUED_IDENTIFIER_KEYS)
            + rb')"\s*:\s*"(?!00000000-0000-4000-8000-\d{12}")',
        ),
    ),
    (
        TELEMETRY_KEY_KIND,
        re.compile(rb"(?:client_metadata|access_programs|chatgpt-account-id|x-codex-[a-z-]+)"),
    ),
    ("email", re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # The backstop for operator text the sanitiser walked past. Both kinds are
    # matched over the whole file, at any nesting depth, so a marker inside a
    # tool call's arguments or output is caught even when no field-walking rule
    # covers that item shape yet. Neither is a path or an identifier, which is
    # why nothing above saw them: a `<timezone>Asia/Seoul</timezone>` and a
    # private skill inventory inside a `function_call_output.output` passed the
    # sanitiser and `--strict` together.
    ("unsanitised_environment_tag", _unsanitised_environment_tag_pattern()),
    ("unsanitised_skill_inventory", _unsanitised_skill_inventory_pattern()),
)


def _identity_patterns() -> tuple[tuple[str, re.Pattern[bytes]], ...]:
    return tuple(
        ("live_identity", re.compile(rb"\b" + re.escape(identity.encode()) + rb"\b"))
        for identity in live_identity_strings()
    )


OPERATOR_PATH_KIND = "operator_path"

# The sanitiser's own pattern, over bytes. Judged everywhere in the file --
# including the ``tools`` regions the sanitiser byte-preserves, because a tool
# description is not always Codex's own text: an MCP server the operator runs
# supplies its own, and an absolute path in one is still the operator's. The
# handful of paths Codex itself emits are cleared by value, in
# ``names_an_operator_location``, which is also what keeps the sanitiser and
# this gate from disagreeing about what an operator path is.
_OPERATOR_PATH_BYTES = re.compile(OPERATOR_PATH.pattern.encode())


def _names_an_operator_location(match: bytes) -> bool:
    # A chunk boundary can split a UTF-8 sequence; a replacement character only
    # ever makes a path *unlike* the exempt values, so the decode fails closed.
    return names_an_operator_location(match.decode("utf-8", "replace"))


def _chunks(path: Path) -> Iterator[bytes]:
    tail = b""
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            sample = tail + chunk
            yield sample
            tail = sample[-_OVERLAP_BYTES:]


def identifier_findings(path: Path) -> list[str]:
    """Identifier-shaped kinds found in ``path``; never the offending value."""

    kinds: set[str] = set()
    patterns = _PATTERNS + _identity_patterns()
    for sample in _chunks(path):
        for label, pattern in patterns:
            if pattern.search(sample):
                kinds.add(label)
        for match in _UUID.finditer(sample):
            if not is_placeholder_uuid(match.group().decode()):
                kinds.add("uuid")
                break
        if any(_names_an_operator_location(match.group()) for match in _OPERATOR_PATH_BYTES.finditer(sample)):
            kinds.add(OPERATOR_PATH_KIND)
    return sorted(kinds)


def _identifier_pass(root: Path, allow_telemetry_keys: frozenset[str]) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    scanned = 0
    for current, _directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted(file_names):
            candidate = current_path / name
            if candidate.is_symlink() or candidate.suffix.casefold() not in IDENTIFIER_SCAN_SUFFIXES:
                continue
            relative = str(candidate.relative_to(root))
            try:
                kinds = identifier_findings(candidate)
            except OSError as exc:
                findings.append({"path": relative, "kinds": [f"read_error:{type(exc).__name__}"]})
                continue
            scanned += 1
            if relative in allow_telemetry_keys:
                kinds = [kind for kind in kinds if kind != TELEMETRY_KEY_KIND]
            if kinds:
                findings.append({"path": relative, "kinds": kinds})
    return findings, scanned


def declared_telemetry_key_bodies(root: Path) -> frozenset[str]:
    """Root-relative bodies that *declare* they carry bare Codex telemetry keys.

    Read from ``provenance.json``: a pre-strip fixture exists to feed
    ``strip_source_telemetry``, and ``carries_client_telemetry`` is where it says
    so. ``provenance.json`` exempts itself for the same reason the README is
    prose -- it *names* the fields the sanitiser removes. Every value-shaped kind
    (a live UUID, a workspace path, an email, this host's identity, a credential
    shape) still applies to all of them.

    A tree without a ``provenance.json`` -- a raw capture directory, say -- gets
    no exemption at all, which is the answer an operator wants there.
    """

    try:
        payload = json.loads((root / PROVENANCE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    fixtures = payload.get("fixtures") if isinstance(payload, dict) else None
    if not isinstance(fixtures, dict):
        return frozenset()
    declared = {
        str(name)
        for name, entry in fixtures.items()
        if isinstance(entry, dict) and entry.get("carries_client_telemetry")
    }
    return frozenset(declared | {PROVENANCE_NAME})


def scan_fixture_tree(
    root: str | Path,
    *,
    allow_telemetry_keys: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Credential scan over every file plus the identifier scan over the bodies.

    The bodies that may carry bare Codex telemetry key names are read from
    ``provenance.json``; ``allow_telemetry_keys`` adds to that, for a tree that
    has no provenance file. Every other kind is rejected everywhere.

    Report shape mirrors ``privacy_scan.scan_tree`` and adds ``bodies_scanned``
    and ``telemetry_key_exemptions``; findings from both passes are merged per
    path.
    """

    root_path = Path(root).resolve()
    exemptions = declared_telemetry_key_bodies(root_path) | allow_telemetry_keys
    credential = scan_tree(root_path)
    identifier, bodies_scanned = _identifier_pass(root_path, exemptions)
    merged: dict[str, set[str]] = {}
    for finding in [*credential["findings"], *identifier]:
        merged.setdefault(str(finding["path"]), set()).update(finding["kinds"])
    findings = [{"path": path, "kinds": sorted(kinds)} for path, kinds in sorted(merged.items())]
    return {
        "schema_version": 1,
        "root": str(root_path),
        "passed": not findings,
        "files_scanned": credential["files_scanned"],
        "bodies_scanned": bodies_scanned,
        "bytes_scanned": credential["bytes_scanned"],
        "telemetry_key_exemptions": sorted(exemptions),
        "findings": findings,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="Optional JSON report destination")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--allow-telemetry-keys",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "Extra root-relative body that may keep bare Codex telemetry key names. "
            "Bodies declaring carries_client_telemetry in provenance.json are already exempt."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = scan_fixture_tree(args.root, allow_telemetry_keys=frozenset(args.allow_telemetry_keys))
    if args.output:
        atomic_write_json(args.output, result)
    exemptions = result["telemetry_key_exemptions"]
    print(
        f"Fixture privacy scan: {'PASS' if result['passed'] else 'FAIL'}; "
        f"{result['files_scanned']} file(s), {result['bodies_scanned']} body/bodies, "
        f"telemetry-key exemption(s): {', '.join(exemptions) if exemptions else 'none'}"
    )
    for finding in result["findings"]:
        print(f"  {finding['path']}: {', '.join(finding['kinds'])}")
    return 2 if args.strict and not result["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
