"""TOTP replay-protection tests for :meth:`ClientStore.verify_totp`.

A 6-digit TOTP code is valid for its whole 30s step (plus drift), so without
bookkeeping the same code could be redeemed twice. ``verify_totp`` records
the last accepted timestep per SEED OWNER and rejects any non-newer code.
For delegated (DCR) clients the key is the owner, so two derived clients
cannot each spend the same code.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pyotp
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from beaconmcp.auth import ClientStore


@pytest.fixture()
def clients(tmp_path: Path) -> ClientStore:
    return ClientStore(tmp_path / "clients.json")


def test_first_use_accepts_then_replay_rejected(clients: ClientStore) -> None:
    client_id, _, seed = clients.create("human")
    code = pyotp.TOTP(seed).now()
    assert clients.verify_totp(client_id, code) is True
    # Same code, same step -> replay, must be rejected.
    assert clients.verify_totp(client_id, code) is False
    # And again.
    assert clients.verify_totp(client_id, code) is False


def test_fresh_code_in_later_step_accepted(clients: ClientStore) -> None:
    client_id, _, seed = clients.create("human")
    totp = pyotp.TOTP(seed)
    now = time.time()
    code_now = totp.at(now)
    code_next = totp.at(now + totp.interval)

    assert clients.verify_totp(client_id, code_now) is True
    # A code from the following 30s step is strictly newer -> accepted,
    # even though the current one was just spent.
    assert clients.verify_totp(client_id, code_next) is True
    # Replaying either of the now-consumed codes still fails.
    assert clients.verify_totp(client_id, code_now) is False
    assert clients.verify_totp(client_id, code_next) is False


def test_wrong_code_does_not_advance_step(clients: ClientStore) -> None:
    """A rejected (wrong) code must not poison the replay counter."""
    client_id, _, seed = clients.create("human")
    assert clients.verify_totp(client_id, "000000") is False
    # A subsequent valid current code is still accepted.
    code = pyotp.TOTP(seed).now()
    assert clients.verify_totp(client_id, code) is True


def test_replay_is_per_owner_not_per_client(clients: ClientStore) -> None:
    """Two derived clients delegating to one owner share the replay window:
    a code spent through one cannot be replayed through the other."""
    owner_id, _, owner_seed = clients.create("human")
    d1, _ = clients.create_dynamic(
        owner_client_id=owner_id, name="d1", registration_source="chatgpt:s1",
    )
    d2, _ = clients.create_dynamic(
        owner_client_id=owner_id, name="d2", registration_source="chatgpt:s2",
    )
    code = pyotp.TOTP(owner_seed).now()
    # First derived client spends the code.
    assert clients.verify_totp(d1, code) is True
    # Second derived client cannot replay the SAME owner code.
    assert clients.verify_totp(d2, code) is False
    # The owner itself cannot replay it either.
    assert clients.verify_totp(owner_id, code) is False


def test_distinct_owners_have_independent_windows(
    clients: ClientStore,
) -> None:
    """Replay state is keyed by owner; unrelated clients are unaffected."""
    a_id, _, a_seed = clients.create("owner_a")
    b_id, _, b_seed = clients.create("owner_b")
    # Each owner's current code is independently valid.
    assert clients.verify_totp(a_id, pyotp.TOTP(a_seed).now()) is True
    assert clients.verify_totp(b_id, pyotp.TOTP(b_seed).now()) is True
    # Replaying owner A's code does not affect owner B (already accepted
    # above; here we just confirm A's replay fails while B is untouched).
    assert clients.verify_totp(a_id, pyotp.TOTP(a_seed).now()) is False
