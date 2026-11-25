from hsmpin import (
    hash_pin,
    is_locked,
    pin_batch,
    reset_counter,
    verify,
)

REGISTERED_PIN = "2468"
SALT = "public-device-salt"
POLICY = {
    "min_length": 4,
    "max_length": 8,
    "allowed_chars": "0123456789",
    "max_failures": 3,
    "lock_seconds": 30,
    "salt": SALT,
}


def make_state(*devices):
    pins = {
        device: {"hash": hash_pin(REGISTERED_PIN, SALT), "salt": SALT}
        for device in devices
    }
    return {"pins": pins, "devices": {}, "policy": dict(POLICY)}


def test_correct_pin_passes_and_clears_previous_failure():
    state = make_state("terminal-a")

    failed = verify(state, "terminal-a", "0000", 100, POLICY)
    passed = verify(state, "terminal-a", REGISTERED_PIN, 101, POLICY)

    assert failed["ok"] is False
    assert passed["ok"] is True
    assert state["devices"]["terminal-a"]["failures"] == 0
    assert state["devices"]["terminal-a"]["last_success"] == 101
    assert is_locked(state, "terminal-a", 101) is False


def test_single_wrong_pin_counts_once_for_that_device():
    state = make_state("terminal-a", "terminal-b")

    verify(state, "terminal-a", "0000", 100, POLICY)
    result = verify(state, "terminal-b", "0000", 101, POLICY)

    assert result["ok"] is False
    assert state["devices"]["terminal-a"]["failures"] == 1
    assert state["devices"]["terminal-b"]["failures"] == 1


def test_consecutive_failures_reach_threshold_and_lock():
    state = make_state("terminal-a")

    result = None
    for offset in range(3):
        result = verify(state, "terminal-a", "0000", 100 + offset, POLICY)

    assert result["ok"] is False
    assert state["devices"]["terminal-a"]["failures"] == 3
    assert result["locked"] is True
    assert is_locked(state, "terminal-a", 103) is True


def test_success_clears_the_failure_counter():
    state = make_state("terminal-a")
    verify(state, "terminal-a", "0000", 100, POLICY)
    verify(state, "terminal-a", "0000", 101, POLICY)

    reset_counter(state, "terminal-a", 102)

    assert state["devices"]["terminal-a"]["failures"] == 0
    assert state["devices"]["terminal-a"]["last_success"] == 102


def test_batch_devices_keep_independent_counters():
    requests = [
        {
            "device": "terminal-a",
            "pin": "0000",
            "pin_hash": hash_pin(REGISTERED_PIN, SALT),
            "salt": SALT,
        },
        {
            "device": "terminal-b",
            "pin": "0000",
            "pin_hash": hash_pin(REGISTERED_PIN, SALT),
            "salt": SALT,
        },
    ]

    batch = pin_batch(requests, POLICY, 100)

    assert batch["terminal-a"]["ok"] is False
    assert batch["terminal-b"]["ok"] is False
    assert batch["terminal-a"]["state"]["devices"]["terminal-a"]["failures"] == 1
    assert batch["terminal-b"]["state"]["devices"]["terminal-b"]["failures"] == 1