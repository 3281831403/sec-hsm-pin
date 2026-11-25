"""PIN verification state machine for a small hardware security module.

The public state is a mapping with three parts:

``pins``
    Registered PIN material per device.  A value may be a mapping with
    ``hash`` (or ``pin_hash``) and ``salt`` entries, or a bare hash string.

``devices``
    Mutable per-device runtime state: failure counter, lock timestamps,
    last success and failure times, and an append-only event trail.

``policy``
    The policy used by the low-level helpers that do not take a policy
    argument themselves, notably ``record_failure``.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping, Sequence
from typing import Any

DEFAULT_POLICY = {
    "min_length": 4,
    "max_length": 8,
    "allowed_chars": "0123456789",
    "max_failures": 3,
    "lock_seconds": 30,
    "salt": "hsmpin-default-salt",
}

# Failure counters are stored per device in the supplied state mapping
# (``state["devices"][device]["failures"]``).  They must never be shared
# process-wide, otherwise activity on one device leaks into another.


def _merge_policy(policy: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = dict(DEFAULT_POLICY)
    if isinstance(policy, Mapping):
        merged.update(policy)
    return merged


def _state_policy(state: dict[str, Any]) -> dict[str, Any]:
    return _merge_policy(state.get("policy"))


def _require_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise TypeError("state must be a dict")
    if not isinstance(state.get("devices", {}), dict):
        raise TypeError("state devices must be a dict")
    if not isinstance(state.get("pins", {}), dict):
        raise TypeError("state pins must be a dict")
    return state


def _blank_entry() -> dict[str, Any]:
    return {
        "failures": 0,
        "locked_at": None,
        "locked_until": None,
        "lock_seconds": 0,
        "last_failure": None,
        "last_success": None,
        "events": [],
    }


def _lookup_entry(state: dict[str, Any], device: str) -> dict[str, Any] | None:
    devices = state.get("devices", {})
    entry = devices.get(device)
    return entry if isinstance(entry, dict) else None


def _ensure_entry(state: dict[str, Any], device: str) -> dict[str, Any]:
    if not isinstance(device, str) or not device:
        raise ValueError("device must be a non-empty string")
    entry = _lookup_entry(state, device)
    if entry is None:
        entry = _blank_entry()
        state.setdefault("devices", {})[device] = entry
    return entry


def _failure_count(state: dict[str, Any], device: str) -> int:
    entry = _lookup_entry(state, device)
    if entry is None:
        return 0
    count = entry.get("failures", 0)
    return count if isinstance(count, int) and not isinstance(count, bool) else 0


def _add_event(entry: dict[str, Any], kind: str, now: Any) -> None:
    events = entry.setdefault("events", [])
    if isinstance(events, list):
        events.append({"kind": kind, "at": now})


def _pin_material(
    state: dict[str, Any], device: str, policy: Mapping[str, Any]
) -> tuple[str | None, Any]:
    record = state.get("pins", {}).get(device)
    expected: str | None = None
    salt: Any = policy.get("salt", "")

    if isinstance(record, Mapping):
        raw_hash = record.get("hash", record.get("pin_hash"))
        expected = raw_hash if isinstance(raw_hash, str) else None
        salt = record.get("salt", salt)
    elif isinstance(record, str):
        expected = record
    else:
        entry = _lookup_entry(state, device)
        if entry is not None:
            raw_hash = entry.get("pin_hash")
            expected = raw_hash if isinstance(raw_hash, str) else None
            salt = entry.get("salt", salt)

    return expected, salt


def validate_pin_format(
    pin: Any, policy: Mapping[str, Any] | None
) -> list[str]:
    """Return the format problems found in *pin*."""
    settings = _merge_policy(policy)
    problems: list[str] = []

    if not isinstance(pin, str):
        return ["pin_type"]

    minimum = int(settings.get("min_length", 4))
    maximum = int(settings.get("max_length", 8))
    if len(pin) < minimum or len(pin) > maximum:
        problems.append("pin_length")

    allowed = settings.get("allowed_chars")
    if allowed is not None:
        if isinstance(allowed, (set, frozenset)):
            allowed_chars = allowed
        else:
            allowed_chars = set(allowed)
        if any(char not in allowed_chars for char in pin):
            problems.append("pin_charset")

    return problems


def hash_pin(pin: str, salt: Any) -> str:
    """Return a stable, device-salted hash for *pin*."""
    if not isinstance(pin, str):
        raise TypeError("pin must be a string")
    if isinstance(salt, bytes):
        salt_material = salt
    else:
        salt_material = str(salt).encode("utf-8")
    material = pin.encode("utf-8")
    return hmac.new(salt_material, material, hashlib.sha256).hexdigest()


def record_failure(
    state: dict[str, Any], device: str, now: Any
) -> dict[str, Any]:
    """Record one failed verification and apply a lock when needed."""
    _require_state(state)
    settings = _state_policy(state)
    limit = int(settings.get("max_failures", 3))
    lock_seconds = int(settings.get("lock_seconds", 30))

    entry = _ensure_entry(state, device)

    # The counter belongs to this device only and lives in the state mapping.
    failures = _failure_count(state, device) + 1
    entry["failures"] = failures
    entry["last_failure"] = now
    entry["lock_seconds"] = lock_seconds
    _add_event(entry, "failure", now)

    if failures >= limit:
        entry["locked_at"] = now
        entry["locked_until"] = now + lock_seconds
    return state


def is_locked(state: dict[str, Any], device: str, now: Any) -> bool:
    """Return whether *device* is still inside its lock period."""
    _require_state(state)
    entry = _lookup_entry(state, device)
    if entry is None:
        return False
    until = entry.get("locked_until")
    if until is None:
        return False
    # The lock has a minimum duration: the device stays locked until the
    # deadline is reached (expired exactly at ``now == locked_until``).
    return now < until


def reset_counter(
    state: dict[str, Any], device: str, now: Any
) -> dict[str, Any]:
    """Clear the lock state and record a successful verification."""
    _require_state(state)
    entry = _ensure_entry(state, device)
    entry["failures"] = 0
    entry["locked_at"] = None
    entry["locked_until"] = None
    entry["last_success"] = now
    _add_event(entry, "success", now)
    return state


def verify(
    state: dict[str, Any],
    device: str,
    pin: Any,
    now: Any,
    policy: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Verify *pin* for *device*, returning the result and updated state."""
    _require_state(state)
    settings = _merge_policy(policy)
    state["policy"] = dict(settings)

    expected, salt = _pin_material(state, device, settings)
    if expected is None:
        return {
            "ok": False,
            "device": device,
            "reason": "unknown_device",
            "locked": False,
            "failure_count": _failure_count(state, device),
            "state": state,
        }

    if is_locked(state, device, now):
        # While locked *every* attempt is rejected.  Do not call
        # ``record_failure`` here: the failure count, the lock deadline and
        # the event trail must stay unchanged for the whole lock period.
        return {
            "ok": False,
            "device": device,
            "reason": "locked",
            "locked": True,
            "failure_count": _failure_count(state, device),
            "state": state,
        }

    problems = validate_pin_format(pin, settings)
    if problems:
        return {
            "ok": False,
            "device": device,
            "reason": "invalid_format",
            "problems": problems,
            "locked": False,
            "failure_count": _failure_count(state, device),
            "state": state,
        }

    actual = hash_pin(pin, salt)
    if hmac.compare_digest(
        actual.encode("utf-8"), expected.encode("utf-8")
    ):
        updated = reset_counter(state, device, now)
        return {
            "ok": True,
            "device": device,
            "reason": "verified",
            "locked": False,
            "failure_count": _failure_count(updated, device),
            "state": updated,
        }

    updated = record_failure(state, device, now)
    return {
        "ok": False,
        "device": device,
        "reason": "wrong_pin",
        "locked": is_locked(updated, device, now),
        "failure_count": _failure_count(updated, device),
        "state": updated,
    }


def validate_state(state: dict[str, Any]) -> list[str]:
    """Return the consistency problems found in *state*."""
    _require_state(state)
    problems: list[str] = []

    for device, entry in state.get("devices", {}).items():
        if not isinstance(entry, dict):
            problems.append(f"{device}: device state is not a mapping")
            continue

        failures = entry.get("failures", 0)
        if (
            not isinstance(failures, int)
            or isinstance(failures, bool)
            or failures < 0
        ):
            problems.append(f"{device}: failure count is negative")

        until = entry.get("locked_until")
        if until is not None:
            if entry.get("locked_at") is None:
                problems.append(f"{device}: lock is missing a start time")
            seconds = entry.get("lock_seconds", 0)
            if not isinstance(seconds, (int, float)) or seconds <= 0:
                problems.append(f"{device}: lock is missing a duration")

        events = entry.get("events")
        if isinstance(events, list):
            previous_at: Any = None
            for event in events:
                if not isinstance(event, Mapping):
                    continue
                at = event.get("at")
                if isinstance(at, bool) or not isinstance(at, (int, float)):
                    continue
                if previous_at is not None and at < previous_at:
                    problems.append(
                        f"{device}: event timestamps are not in chronological order"
                    )
                    break
                previous_at = at

    return problems


def pin_batch(
    requests: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any] | None,
    now: Any,
) -> dict[str, dict[str, Any]]:
    """Verify independent PIN attempts for several devices."""
    settings = _merge_policy(policy)
    state: dict[str, Any] = {
        "pins": {},
        "devices": {},
        "policy": dict(settings),
    }

    prepared: list[tuple[str, Any]] = []
    for request in requests:
        if not isinstance(request, Mapping):
            raise TypeError("each request must be a mapping")
        device = request["device"]
        pin = request["pin"]
        salt = request.get("salt", settings.get("salt", ""))
        pin_hash = request.get("pin_hash")
        if pin_hash is None:
            expected_pin = request.get("expected_pin")
            if expected_pin is None:
                raise ValueError("request needs pin_hash or expected_pin")
            pin_hash = hash_pin(expected_pin, salt)
        state["pins"][device] = {"hash": pin_hash, "salt": salt}
        prepared.append((device, pin))

    results: dict[str, dict[str, Any]] = {}
    for device, pin in prepared:
        # Every device keeps its own entry; never carry one device's failure
        # count over to the next device in the batch.
        result = verify(state, device, pin, now, settings)
        results[device] = result
    return results
