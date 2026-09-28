import json
from copy import deepcopy
from typing import cast

import pytest

from app.core.openai.requests import ResponsesRequest
from app.core.types import JsonValue
from app.modules.proxy import service as proxy_service
from app.modules.proxy._service.websocket.helpers import (
    _install_verified_fresh_replay,
    _prepare_websocket_request_state_for_account_switch,
    _project_websocket_full_resend_for_replay,
    _websocket_request_text_is_account_neutral_fresh_replay,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("lite", "reasoning", "expected"),
    [
        (True, {"context": "all_turns", "effort": "high"}, True),
        (False, {"context": "all_turns"}, False),
        (True, {"context": "last_turn"}, False),
        (True, {"context": {"id": "rs_owner"}}, False),
        (True, {"context": "all_turns", "unknown": "value"}, False),
    ],
)
def test_websocket_lite_replay_accepts_only_canonical_context(lite, reasoning, expected):
    items = [{"role": "user", "content": "hello"}]
    if lite:
        items.insert(0, {"type": "additional_tools", "role": "developer", "tools": []})
    payload = {"type": "response.create", "model": "gpt-5.4", "input": items, "reasoning": reasoning}
    assert _websocket_request_text_is_account_neutral_fresh_replay(json.dumps(payload)) is expected


@pytest.mark.parametrize("unsafe", [None, "missing_reply", "unpaired_call", "file", "prompt", "unknown_type"])
def test_full_resend_projection_preserves_content_and_rejects_unsafe_replay(unsafe: str | None) -> None:
    """Project response-owned fields only when the complete payload remains portable."""
    user = {"role": "user", "content": "hello"}
    call = {"type": "function_call", "id": "fc_owner", "call_id": "call_1", "name": "read", "arguments": "{}"}
    output = {"type": "function_call_output", "call_id": "call_1", "output": "file contents"}
    assistant = {
        "type": "message",
        "id": "msg_owner",
        "role": "assistant",
        "content": [{"type": "output_text", "text": "Done"}],
    }
    follow_up = {"role": "user", "content": "continue"}
    items = [
        user,
        {"type": "reasoning", "id": "rs_owner", "encrypted_content": "ciphertext", "summary": []},
        call,
        output,
        assistant,
        follow_up,
    ]
    if unsafe == "missing_reply":
        items.remove(assistant)
    elif unsafe == "unpaired_call":
        items.remove(output)
    elif unsafe == "file":
        follow_up["content"] = [{"type": "input_file", "file_id": "file_owner"}]
    payload = ResponsesRequest.model_validate(
        {
            "type": "unknown" if unsafe == "unknown_type" else "response.create",
            "model": "gpt-5.4",
            "instructions": "",
            "input": items,
            **({"prompt": {"id": "pmpt_owner"}} if unsafe == "prompt" else {}),
        }
    )
    payload = dict(payload.to_replay_safety_payload())
    original = deepcopy(payload)

    projected = _project_websocket_full_resend_for_replay(payload, stored_count=1)

    assert payload == original
    if unsafe is not None:
        assert projected is None
    else:
        assert projected is not None
        assert projected["input"] == [
            user,
            {key: value for key, value in call.items() if key != "id"},
            output,
            {key: value for key, value in assistant.items() if key != "id"},
            follow_up,
        ]


def test_size_slimmed_resend_does_not_preserve_client_fingerprint() -> None:
    """A slimmed retry must refresh identity so later turns resend missing context."""
    items: list[JsonValue] = [
        {"role": "user", "content": [{"type": "input_image", "image_url": "data:image/png;base64," + "A" * 6000}]},
        {"type": "reasoning", "encrypted_content": "owner-ciphertext"},
        {"type": "function_call", "call_id": "call_1", "name": "read", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "call_1", "output": "historical output " * 1000},
        {"role": "assistant", "content": "Done"},
        {"role": "user", "content": "continue"},
    ]
    payload: dict[str, JsonValue] = {"type": "response.create", "model": "gpt-5.4", "input": items}
    slimmed, stats = proxy_service._slim_response_create_payload_for_upstream(payload, max_bytes=1024)
    assert stats is not None
    assert slimmed["input"] != items
    original_fingerprint = proxy_service._fingerprint_input_items(items)
    state = proxy_service._WebSocketRequestState(
        request_id="slimmed-replay",
        model="gpt-5.4",
        service_tier=None,
        reasoning_effort=None,
        api_key_reservation=None,
        started_at=0.0,
        previous_response_id="resp_owner",
        preferred_account_id="account_owner",
        proxy_injected_previous_response_id=True,
        fresh_upstream_request_is_retry_safe=True,
        fresh_upstream_request_stored_input_count=4,
        fresh_upstream_request_text=json.dumps(slimmed),
        input_item_count=len(items),
        input_full_fingerprint=original_fingerprint,
    )

    assert _prepare_websocket_request_state_for_account_switch(state) is None
    assert _install_verified_fresh_replay(state, require_account_neutral=False) is not None
    assert state.input_full_fingerprint != original_fingerprint
    assert state.input_full_fingerprint == proxy_service._fingerprint_input_items(
        cast(list[JsonValue], slimmed["input"])
    )


@pytest.mark.parametrize(
    "protected", ["file", "turn_state", "created", "event", "sequence", "not_native", "policy", "no_anchor"]
)
def test_owner_recovery_signal_respects_independent_ownership_and_output(protected):
    from app.modules.proxy._service.websocket.helpers import _websocket_request_client_owner_recovery

    continuity = proxy_service._WebSocketContinuityState()
    state = proxy_service._WebSocketRequestState(
        request_id="recovery",
        model="gpt-5.4",
        service_tier=None,
        reasoning_effort=None,
        api_key_reservation=None,
        started_at=0.0,
        previous_response_id="resp_old",
        preferred_account_id="account_a",
        client_recovery_continuity=continuity,
        previous_response_owner_recovery_allowed=True,
        expose_stale_previous_response_classifier=True,
    )
    if protected == "file":
        state.file_required_preferred_account = True
    elif protected == "turn_state":
        state.affinity_policy = proxy_service._AffinityPolicy(codex_session_source="turn_state")
    elif protected == "created":
        state.response_id = "resp_accepted"
    elif protected == "event":
        state.response_event_count = 1
    elif protected == "sequence":
        state.last_downstream_sequence_number = 0
    elif protected == "not_native":
        state.expose_stale_previous_response_classifier = False
    elif protected == "policy":
        state.previous_response_owner_recovery_allowed = False
    elif protected == "no_anchor":
        state.previous_response_id = None
    assert not _websocket_request_client_owner_recovery(state)
    assert continuity.unavailable_owner_account_id is None


@pytest.mark.parametrize(
    "item",
    [
        {"type": "compaction", "encrypted_content": "opaque"},
        {"type": "item_reference", "id": "old_item"},
        {"type": "function_call_output", "call_id": "missing_call", "output": "result"},
        {"role": "user", "content": [{"type": "input_file", "file_id": "old_file"}]},
    ],
)
def test_client_recovery_projection_rejects_nonportable_history(item):
    from app.modules.proxy._service.websocket.helpers import _project_websocket_client_recovery_payload

    payload = {"model": "gpt-5.4", "input": [{"role": "user", "content": "hello"}, item]}
    assert _project_websocket_client_recovery_payload(payload) is None


@pytest.mark.parametrize(
    ("metadata", "portable"),
    [
        ({"session_id": "session", "thread_id": "thread", "turn_id": "turn"}, True),
        ({"thread_id": {"id": "owner"}}, False),
        ({"thread_id": " "}, False),
        ({"unknown_owner": "owner"}, False),
        ({"x-codex-turn-state": "owner"}, False),
    ],
)
def test_native_trace_metadata_is_portable_but_owner_state_is_not(metadata, portable):
    payload = {"model": "gpt-5.4", "input": [{"role": "user", "content": "hello"}], "client_metadata": metadata}
    assert _websocket_request_text_is_account_neutral_fresh_replay(json.dumps(payload)) is portable


@pytest.mark.parametrize(
    ("tool", "portable"),
    [
        ({"type": "namespace", "name": "functions", "tools": [{"type": "function", "name": "read"}]}, True),
        (
            {
                "type": "namespace",
                "name": "functions",
                "tools": [{"type": "file_search", "vector_store_ids": ["vs_old"]}],
            },
            False,
        ),
        (
            {
                "type": "namespace",
                "name": "functions",
                "tools": [{"type": "function", "name": "read", "container_id": "old"}],
            },
            False,
        ),
        ({"type": "namespace", "name": "functions", "tools": []}, False),
        (
            {"type": "namespace", "name": "functions", "tools": [{"type": "namespace", "name": "nested", "tools": []}]},
            False,
        ),
        ({"type": "web_search", "external_web_access": False}, True),
        ({"type": "web_search", "external_web_access": True}, True),
        ({"type": "web_search", "external_web_access": "true"}, False),
        ({"type": "web_search", "external_web_access": {"file_id": "old"}}, False),
    ],
)
def test_native_tool_declarations_preserve_account_ownership(tool, portable):
    payload = {"model": "gpt-5.4", "input": [{"role": "user", "content": "hello"}], "tools": [tool]}
    assert _websocket_request_text_is_account_neutral_fresh_replay(json.dumps(payload)) is portable
