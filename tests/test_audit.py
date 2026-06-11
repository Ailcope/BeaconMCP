"""Tests for the JSON-lines audit logger."""

from __future__ import annotations

import json
import logging

from beaconmcp import audit


def test_emit_writes_json_line(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="beaconmcp.audit"):
        audit.emit("auth.login", client_id="c1", outcome="ok")
    rec = caplog.records[-1]
    data = json.loads(rec.getMessage())
    assert data["event"] == "auth.login"
    assert data["client_id"] == "c1"
    assert data["outcome"] == "ok"
    assert "ts" in data


def test_redacts_sensitive_fields(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="beaconmcp.audit"):
        audit.emit(
            "tool.call",
            tool="ssh_run",
            args={"host": "pve1", "password": "hunter2", "nested": {"token": "abc"}},
        )
    data = json.loads(caplog.records[-1].getMessage())
    assert data["args"]["host"] == "pve1"
    assert data["args"]["password"] == "***"
    assert data["args"]["nested"]["token"] == "***"


def test_emit_never_raises(monkeypatch) -> None:
    def boom(_msg: str) -> None:
        raise RuntimeError("sink died")

    monkeypatch.setattr(audit._logger, "info", boom)
    # Should swallow the exception -- audit must never break a request.
    audit.emit("anything", x=1)


def test_redacts_top_level_fields(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="beaconmcp.audit"):
        audit.emit("auth.authorize.ok", client_id="c1", totp="123456")
    data = json.loads(caplog.records[-1].getMessage())
    assert data["client_id"] == "c1"
    assert data["totp"] == "***"


def test_compact_args_collapses_long_strings() -> None:
    out = audit.compact_args({"node": "pve1", "blob": "x" * 500})
    assert out["node"] == "pve1"
    assert out["blob"] == "<str:500 chars>"


def test_compact_args_always_collapses_content_keys() -> None:
    # Short command lines / file payloads can embed secrets that key-based
    # redaction cannot see -- they must never reach the sink verbatim.
    out = audit.compact_args({
        "command": "mysql -u root -phunter2 db",
        "content": "DB_PASSWORD=hunter2",
        "path": "/root/.env",
    })
    assert "hunter2" not in str(out)
    assert out["command"] == "<str:26 chars>"
    assert out["content"] == "<str:19 chars>"
    assert out["path"] == "/root/.env"
