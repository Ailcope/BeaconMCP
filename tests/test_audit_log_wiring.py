"""Tests for the audit-log file wiring in the CLI entrypoint."""

from __future__ import annotations

import logging
import stat
from pathlib import Path

import pytest

from beaconmcp.__main__ import _configure_audit_log


@pytest.fixture(autouse=True)
def _clean_audit_handlers():
    """Detach any file handler the test wired so runs stay independent."""
    logger = logging.getLogger("beaconmcp.audit")
    before = list(logger.handlers)
    yield
    for h in logger.handlers[:]:
        if h not in before:
            logger.removeHandler(h)
            h.close()


def test_audit_file_created_owner_only(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "audit.log"
    monkeypatch.setenv("BEACONMCP_AUDIT_LOG", str(target))
    _configure_audit_log()
    assert target.exists()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_env_var_wins_over_config_value(tmp_path: Path, monkeypatch) -> None:
    env_target = tmp_path / "from-env.log"
    monkeypatch.setenv("BEACONMCP_AUDIT_LOG", str(env_target))
    _configure_audit_log(str(tmp_path / "from-config.log"))
    assert env_target.exists()
    assert not (tmp_path / "from-config.log").exists()


def test_config_value_used_without_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("BEACONMCP_AUDIT_LOG", raising=False)
    target = tmp_path / "from-config.log"
    _configure_audit_log(str(target))
    assert target.exists()


def test_dash_disables_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BEACONMCP_AUDIT_LOG", "-")
    logger = logging.getLogger("beaconmcp.audit")
    before = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    _configure_audit_log(str(tmp_path / "ignored.log"))
    after = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert before == after
    assert not (tmp_path / "ignored.log").exists()


def test_unwritable_path_degrades_gracefully(tmp_path: Path, monkeypatch) -> None:
    blocker = tmp_path / "blocked"
    blocker.write_text("not a dir")
    monkeypatch.setenv("BEACONMCP_AUDIT_LOG", str(blocker / "audit.log"))
    # Must warn and keep going, never raise.
    _configure_audit_log()
