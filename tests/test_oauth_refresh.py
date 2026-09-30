"""OAuth refresh tokens (rotation + reuse detection) and OAuth-token persistence.

The claude.ai connector used to drop to "needs authentication" on every
restart (OAuth bearers lived in memory only) and at least once a day (24 h
access token, no refresh token). These tests pin both fixes.
"""

from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from beaconmcp.auth import RefreshTokenError, TokenStore


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# --- issuance ----------------------------------------------------------------


def test_authorization_code_grant_returns_refresh_token() -> None:
    store = TokenStore()
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.access_token and grant.refresh_token
    assert grant.access_token != grant.refresh_token
    assert grant.expires_in == TokenStore.TOKEN_TTL
    assert store.validate(grant.access_token) == "client-a"


def test_client_credentials_grant_has_no_refresh_token() -> None:
    store = TokenStore()
    grant = store.issue_oauth("client-a")
    assert grant.refresh_token is None
    assert store.validate(grant.access_token) == "client-a"


def test_refresh_token_is_not_a_valid_bearer() -> None:
    store = TokenStore()
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None
    assert store.validate(grant.refresh_token) is None


# --- refresh + rotation ------------------------------------------------------


def test_refresh_issues_new_access_and_refresh_token() -> None:
    store = TokenStore()
    first = store.issue_oauth("client-a", refresh=True)
    assert first.refresh_token is not None
    second = store.refresh(first.refresh_token, "client-a")
    assert second.refresh_token is not None
    assert second.access_token != first.access_token
    assert second.refresh_token != first.refresh_token
    assert store.validate(second.access_token) == "client-a"
    # Old access token is untouched: it simply runs out its own TTL.
    assert store.validate(first.access_token) == "client-a"


def test_refresh_rotates_old_refresh_token_out() -> None:
    store = TokenStore()
    first = store.issue_oauth("client-a", refresh=True)
    assert first.refresh_token is not None
    second = store.refresh(first.refresh_token, "client-a")
    assert second.refresh_token is not None
    # The rotated-out token can't be used again, the new one can.
    with pytest.raises(RefreshTokenError):
        store.refresh(first.refresh_token, "client-a")


def test_replayed_refresh_token_revokes_whole_family() -> None:
    store = TokenStore()
    first = store.issue_oauth("client-a", refresh=True)
    assert first.refresh_token is not None
    second = store.refresh(first.refresh_token, "client-a")
    assert second.refresh_token is not None

    with pytest.raises(RefreshTokenError) as exc:
        store.refresh(first.refresh_token, "client-a")
    assert exc.value.reason == "reused"

    # Every token of the family is dead: the legitimate holder has to
    # re-authenticate, and so does whoever replayed the stolen token.
    assert store.validate(first.access_token) is None
    assert store.validate(second.access_token) is None
    with pytest.raises(RefreshTokenError):
        store.refresh(second.refresh_token, "client-a")


def test_reuse_does_not_touch_other_families() -> None:
    store = TokenStore()
    a = store.issue_oauth("client-a", refresh=True)
    b = store.issue_oauth("client-a", refresh=True)
    assert a.refresh_token is not None and b.refresh_token is not None
    store.refresh(a.refresh_token, "client-a")
    with pytest.raises(RefreshTokenError):
        store.refresh(a.refresh_token, "client-a")
    assert store.validate(b.access_token) == "client-a"
    store.refresh(b.refresh_token, "client-a")


def test_refresh_with_wrong_client_rejected() -> None:
    store = TokenStore()
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None
    with pytest.raises(RefreshTokenError) as exc:
        store.refresh(grant.refresh_token, "client-b")
    assert exc.value.reason == "invalid"
    # The rightful owner can still use it.
    store.refresh(grant.refresh_token, "client-a")


def test_unknown_refresh_token_rejected() -> None:
    store = TokenStore()
    with pytest.raises(RefreshTokenError) as exc:
        store.refresh("not-a-token", "client-a")
    assert exc.value.reason == "invalid"


def test_expired_refresh_token_rejected() -> None:
    store = TokenStore(refresh_token_ttl=60)
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None
    store._refresh_tokens[_sha(grant.refresh_token)].expires_at = time.time() - 1
    with pytest.raises(RefreshTokenError) as exc:
        store.refresh(grant.refresh_token, "client-a")
    assert exc.value.reason == "expired"


def test_refresh_token_ttl_is_configurable() -> None:
    store = TokenStore(refresh_token_ttl=3600)
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None
    rt = store._refresh_tokens[_sha(grant.refresh_token)]
    assert 3590 < rt.expires_at - time.time() <= 3600


def test_refresh_token_ttl_defaults_to_30_days() -> None:
    assert TokenStore().refresh_token_ttl == 3600 * 24 * 30


def test_refresh_token_ttl_zero_never_expires() -> None:
    store = TokenStore(refresh_token_ttl=0)
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None
    assert store._refresh_tokens[_sha(grant.refresh_token)].expires_at == float("inf")


# --- revocation --------------------------------------------------------------


def test_revoke_client_drops_access_and_refresh_tokens(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    a = store.issue_oauth("client-a", refresh=True)
    b = store.issue_oauth("client-b", refresh=True)
    assert a.refresh_token is not None and b.refresh_token is not None

    assert store.revoke_client("client-a") == 1
    assert store.validate(a.access_token) is None
    with pytest.raises(RefreshTokenError):
        store.refresh(a.refresh_token, "client-a")
    assert store.validate(b.access_token) == "client-b"

    reborn = TokenStore(db_path=db)
    assert reborn.validate(a.access_token) is None
    assert reborn.validate(b.access_token) == "client-b"


def test_end_session_revoke_kills_refresh_family() -> None:
    store = TokenStore()
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None
    assert store.revoke(grant.access_token) is True
    # Grace window keeps the in-flight response alive...
    assert store.validate(grant.access_token) == "client-a"
    # ...but the client can't silently mint a fresh bearer afterwards.
    with pytest.raises(RefreshTokenError):
        store.refresh(grant.refresh_token, "client-a")


def test_prune_unknown_clients(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    keep = store.issue_oauth("client-a", refresh=True)
    gone = store.issue_oauth("client-gone", refresh=True)

    reborn = TokenStore(db_path=db)
    reborn.prune_unknown_clients({"client-a"})
    assert reborn.validate(keep.access_token) == "client-a"
    assert reborn.validate(gone.access_token) is None


# --- persistence -------------------------------------------------------------


def test_oauth_access_token_survives_restart(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    grant = store.issue_oauth("client-a", refresh=True)
    cc = store.issue_oauth("client-cli")

    reborn = TokenStore(db_path=db)
    assert reborn.validate(grant.access_token) == "client-a"
    assert reborn.validate(cc.access_token) == "client-cli"


def test_refresh_token_survives_restart(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None

    reborn = TokenStore(db_path=db)
    fresh = reborn.refresh(grant.refresh_token, "client-a")
    assert reborn.validate(fresh.access_token) == "client-a"


def test_reuse_detected_across_restart(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    first = store.issue_oauth("client-a", refresh=True)
    assert first.refresh_token is not None
    second = store.refresh(first.refresh_token, "client-a")

    reborn = TokenStore(db_path=db)
    with pytest.raises(RefreshTokenError) as exc:
        reborn.refresh(first.refresh_token, "client-a")
    assert exc.value.reason == "reused"
    assert reborn.validate(second.access_token) is None

    # The family revocation itself is durable too.
    again = TokenStore(db_path=db)
    assert again.validate(second.access_token) is None


def test_oauth_tokens_stored_hashed(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    grant = store.issue_oauth("client-a", refresh=True)
    assert grant.refresh_token is not None
    raw = db.read_bytes()
    assert grant.access_token.encode() not in raw
    assert grant.refresh_token.encode() not in raw
    assert store._db is not None
    hashes = {
        r[0] for r in store._db.execute("SELECT token_hash FROM oauth_tokens")
    } | {r[0] for r in store._db.execute("SELECT token_hash FROM refresh_tokens")}
    assert _sha(grant.access_token) in hashes
    assert _sha(grant.refresh_token) in hashes


def test_expired_oauth_rows_purged_on_load(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    grant = store.issue_oauth("client-a", refresh=True)
    assert store._db is not None
    store._db.execute("UPDATE oauth_tokens SET expires_at = 1.0")
    store._db.execute("UPDATE refresh_tokens SET expires_at = 1.0")
    store._db.commit()

    reborn = TokenStore(db_path=db)
    assert reborn.validate(grant.access_token) is None
    assert reborn._db is not None
    assert reborn._db.execute("SELECT COUNT(*) FROM oauth_tokens").fetchone()[0] == 0
    assert reborn._db.execute("SELECT COUNT(*) FROM refresh_tokens").fetchone()[0] == 0


def test_dashboard_session_bearer_still_memory_only(tmp_path: Path) -> None:
    db = tmp_path / "tokens.db"
    store = TokenStore(db_path=db)
    session, _ = store.issue("client-a")
    reborn = TokenStore(db_path=db)
    assert reborn.validate(session) is None


def test_existing_named_tokens_db_upgrades_in_place(tmp_path: Path) -> None:
    # A tokens.db written by a release without OAuth persistence only has
    # the named_tokens table; opening it must add the new tables and keep
    # the named tokens.
    db = tmp_path / "tokens.db"
    import sqlite3

    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE named_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL,"
        " name TEXT NOT NULL, expires_at REAL NOT NULL, created_at REAL NOT NULL)"
    )
    conn.execute(
        "INSERT INTO named_tokens VALUES (?, ?, ?, ?, ?)",
        ("legacy-token", "client-a", "laptop", time.time() + 3600, time.time()),
    )
    conn.commit()
    conn.close()

    store = TokenStore(db_path=db)
    assert store.validate("legacy-token") == "client-a"
    grant = store.issue_oauth("client-a", refresh=True)
    assert TokenStore(db_path=db).validate(grant.access_token) == "client-a"


# --- metadata ----------------------------------------------------------------


def test_metadata_advertises_refresh_token_grant() -> None:
    from beaconmcp.__main__ import _oauth_server_metadata

    meta = _oauth_server_metadata("https://beacon.example")
    assert "refresh_token" in meta["grant_types_supported"]
    assert "authorization_code" in meta["grant_types_supported"]
    assert "client_credentials" in meta["grant_types_supported"]
    assert meta["token_endpoint"] == "https://beacon.example/oauth/token"


# --- config ------------------------------------------------------------------


def test_refresh_token_ttl_from_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from beaconmcp.config import Config, ConfigError

    monkeypatch.setenv("VPS_PW", "pw")
    base = """
version: 1
server:
  refresh_token_ttl: {value}
ssh:
  hosts:
    - name: vps1
      host: 198.51.100.10
      user: root
      password: ${{VPS_PW}}
"""

    def load(value: int) -> Config:
        path = tmp_path / f"cfg{value}.yaml"
        path.write_text(base.format(value=value), encoding="utf-8")
        return Config.load(config_path=path)

    assert load(86400).server.refresh_token_ttl == 86400
    # 0 is a deliberate setting (never expires) and must survive parsing.
    assert load(0).server.refresh_token_ttl == 0
    with pytest.raises(ConfigError, match="refresh_token_ttl"):
        load(-1)


def test_refresh_token_ttl_round_trips_through_wizard(tmp_path: Path) -> None:
    from beaconmcp.wizard import load_yaml_into_draft, render_yaml

    cfg = tmp_path / "beaconmcp.yaml"
    cfg.write_text("version: 1\nserver:\n  refresh_token_ttl: 0\n", encoding="utf-8")
    draft = load_yaml_into_draft(cfg)
    assert draft.server.refresh_token_ttl == "0"
    assert "refresh_token_ttl: 0" in render_yaml(draft)
