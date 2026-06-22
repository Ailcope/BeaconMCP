"""Tests for the thread-safety of :class:`ProxmoxClient`'s connection cache.

Sync Proxmox tools now run on a worker-thread pool (see
``server._metric_tool``), so ``_get_connection`` is hit concurrently. The
cache must hand back a valid connection from every thread, create exactly
one connection per node, and never corrupt the backing dict.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import beaconmcp.proxmox.client as client_mod
from beaconmcp.proxmox.client import NodeNotFoundError, ProxmoxClient


class _FakeNode:
    def __init__(self, name: str) -> None:
        self.name = name
        self.host = f"{name}.example.com"
        self.token_id = "root@pam!mytoken"
        self.token_secret = "secret"


class _FakeConfig:
    """Minimal stand-in exposing only what ProxmoxClient touches."""

    def __init__(self, node_names: list[str]) -> None:
        self.pve_nodes = [_FakeNode(n) for n in node_names]
        self.verify_ssl = False

    def get_node(self, name: str) -> _FakeNode | None:
        for n in self.pve_nodes:
            if n.name == name:
                return n
        return None


@pytest.fixture()
def fake_proxmox_api(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Replace ``ProxmoxAPI`` with a counting dummy.

    Returns the list of constructed dummies so a test can assert how many
    connections were built.
    """
    built: list[object] = []
    build_lock = threading.Lock()

    class _DummyAPI:
        def __init__(self, host: str, **kwargs: object) -> None:
            self.host = host
            self.kwargs = kwargs
            with build_lock:
                built.append(self)

    monkeypatch.setattr(client_mod, "ProxmoxAPI", _DummyAPI)
    return built


def test_get_connection_caches_per_node(fake_proxmox_api: list[object]) -> None:
    c = ProxmoxClient(_FakeConfig(["pve1"]))
    first = c._get_connection("pve1")
    second = c._get_connection("pve1")
    assert first is second
    assert len(fake_proxmox_api) == 1


def test_get_connection_unknown_node_raises(
    fake_proxmox_api: list[object],
) -> None:
    c = ProxmoxClient(_FakeConfig(["pve1"]))
    with pytest.raises(NodeNotFoundError):
        c._get_connection("nope")


def test_concurrent_get_connection_single_node(
    fake_proxmox_api: list[object],
) -> None:
    """Many threads racing for the same node all get a valid, identical
    connection and the cache is not corrupted."""
    c = ProxmoxClient(_FakeConfig(["pve1"]))

    barrier = threading.Barrier(20)
    results: list[object] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            conn = c._get_connection("pve1")
            with lock:
                results.append(conn)
        except Exception as e:  # pragma: no cover - failure path
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"unexpected errors: {errors}"
    assert len(results) == 20
    # Every thread observed the exact same cached connection object.
    assert all(r is results[0] for r in results)
    # The cache holds exactly one entry for the node.
    assert list(c._connections) == ["pve1"]


def test_concurrent_get_connection_many_nodes(
    fake_proxmox_api: list[object],
) -> None:
    """Threads hammering several distinct nodes end up with one connection
    per node and no dropped/duplicated cache entries."""
    node_names = [f"pve{i}" for i in range(8)]
    c = ProxmoxClient(_FakeConfig(node_names))

    barrier = threading.Barrier(len(node_names) * 4)
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker(name: str) -> None:
        barrier.wait()
        try:
            for _ in range(5):
                conn = c._get_connection(name)
                assert conn.host == f"{name}.example.com"
        except Exception as e:  # pragma: no cover - failure path
            with lock:
                errors.append(e)

    threads = [
        threading.Thread(target=worker, args=(name,))
        for name in node_names
        for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"unexpected errors: {errors}"
    assert sorted(c._connections) == sorted(node_names)
