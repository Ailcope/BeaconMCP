"""Unit tests for TokenStore named-token persistence (SQLite)."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from beaconmcp.auth import TokenCapExceeded, TokenStore


def test_named_token_survives_restart(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    token, _ = store.issue("client-a", name="laptop")

    reborn = TokenStore(db_path=db)
    assert reborn.validate(token) == "client-a"


def test_internal_bearer_does_not_persist(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    session, _ = store.issue("client-a")  # unnamed: dashboard session bearer

    reborn = TokenStore(db_path=db)
    assert reborn.validate(session) is None


def test_db_file_is_owner_only(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    TokenStore(db_path=db)
    assert stat.S_IMODE(db.stat().st_mode) == 0o600


def test_revoked_token_not_resurrected_by_restart(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    token, _ = store.issue("client-a", name="laptop")
    store.revoke(token)
    # Still valid in-process during the grace window...
    assert store.validate(token) == "client-a"
    # ...but a restart inside that window must not bring it back.
    reborn = TokenStore(db_path=db)
    assert reborn.validate(token) is None


def test_expired_rows_dropped_on_load(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    token, _ = store.issue("client-a", name="laptop")
    # Force expiry, then simulate the process being down past the TTL.
    store._tokens[token].expires_at = 1.0
    store._persist(store._tokens[token])

    reborn = TokenStore(db_path=db)
    assert reborn.validate(token) is None
    assert reborn._db is not None
    rows = reborn._db.execute("SELECT COUNT(*) FROM named_tokens").fetchone()
    assert rows[0] == 0


def test_named_cap_enforced_after_reload(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    for i in range(TokenStore.NAMED_TOKEN_CAP):
        store.issue("client-b", name=f"t{i}")

    reborn = TokenStore(db_path=db)
    with pytest.raises(TokenCapExceeded):
        reborn.issue("client-b", name="one-too-many")


def test_named_token_uses_configured_ttl(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db, named_token_ttl=7200)
    _, expires_in = store.issue("client-a", name="laptop")
    assert expires_in == 7200


def test_internal_bearer_keeps_24h_ttl_regardless(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db, named_token_ttl=7200)
    _, expires_in = store.issue("client-a")  # unnamed: session bearer
    assert expires_in == TokenStore.TOKEN_TTL


def test_named_ttl_defaults_to_30_days(tmp_path: Path) -> None:
    store = TokenStore(db_path=tmp_path / "tokens.db")
    _, expires_in = store.issue("client-a", name="laptop")
    assert expires_in == TokenStore.NAMED_TOKEN_TTL == 3600 * 24 * 30


def test_unwritable_db_degrades_to_memory_only(tmp_path: Path) -> None:
    target = tmp_path / "blocked"
    target.write_text("not a directory")
    store = TokenStore(db_path=target / "tokens.db")
    assert store._db is None
    # The store keeps working in-memory.
    token, _ = store.issue("client-c", name="laptop")
    assert store.validate(token) == "client-c"
