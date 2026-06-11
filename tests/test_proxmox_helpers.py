"""Unit tests for proxmox tool helpers: backup-type detection and the
guest-agent file-size pre-flight."""

from __future__ import annotations

import base64

from beaconmcp.proxmox.system import _qemu_file_size
from beaconmcp.proxmox.vms import _detect_backup_type


class FakeClient:
    """Minimal ProxmoxClient stand-in: canned post/get responses."""

    def __init__(self, post_resp=None, get_resps=None):
        self.post_resp = post_resp
        self.get_resps = list(get_resps or [])
        self.post_kwargs: dict = {}
        self.get_paths: list[str] = []

    def post(self, node, path, **kwargs):
        self.post_kwargs = kwargs
        return self.post_resp

    def get(self, node, path, **kwargs):
        self.get_paths.append(path)
        return self.get_resps.pop(0) if self.get_resps else {}


# --- _detect_backup_type ---------------------------------------------------


def test_backup_type_vzdump_names_no_api_call() -> None:
    c = FakeClient()
    assert _detect_backup_type(
        c, "n", "local:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst"
    ) == "qemu"
    assert _detect_backup_type(
        c, "n", "local:backup/vzdump-lxc-200-2026_01_01-00_00_00.tar.zst"
    ) == "lxc"
    assert c.get_paths == []


def test_backup_type_pbs_namespaces() -> None:
    c = FakeClient()
    assert _detect_backup_type(c, "n", "pbs:backup/vm/100/2026-01-01T00:00:00Z") == "qemu"
    assert _detect_backup_type(c, "n", "pbs:backup/ct/200/2026-01-01T00:00:00Z") == "lxc"
    # A *namespace* literally named "vm" must not shadow the real type segment.
    assert _detect_backup_type(
        c, "n", "pbs:backup/ns/vm/ct/200/2026-01-01T00:00:00Z"
    ) == "lxc"
    assert c.get_paths == []


def test_backup_type_content_lookup_fallback() -> None:
    c = FakeClient(get_resps=[[{"volid": "st:backup/renamed.bin", "subtype": "lxc"}]])
    assert _detect_backup_type(c, "n", "st:backup/renamed.bin") == "lxc"
    assert c.get_paths == ["nodes/n/storage/st/content"]


def test_backup_type_content_lookup_format_fallback() -> None:
    c = FakeClient(get_resps=[[{"volid": "st:backup/renamed.bin", "format": "vma.zst"}]])
    assert _detect_backup_type(c, "n", "st:backup/renamed.bin") == "qemu"


def test_backup_type_tolerates_garbage_content() -> None:
    # Non-dict items in the listing must be skipped, not crash.
    c = FakeClient(get_resps=[
        ["garbage", {"volid": "st:backup/x.bin", "subtype": "qemu"}],
    ])
    assert _detect_backup_type(c, "n", "st:backup/x.bin") == "qemu"


def test_backup_type_undeterminable() -> None:
    assert _detect_backup_type(FakeClient(get_resps=[{"error": "boom"}]),
                               "n", "st:backup/renamed.bin") is None
    # No storage prefix -> no lookup possible.
    assert _detect_backup_type(FakeClient(), "n", "renamed.bin") is None


# --- _qemu_file_size -------------------------------------------------------


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_file_size_nominal_base64() -> None:
    c = FakeClient(
        post_resp={"pid": 7},
        get_resps=[{
            "exited": 1, "exitcode": 0,
            "out-data": _b64("2048576\n"), "out-data-encoding": "base64",
        }],
    )
    assert _qemu_file_size(c, "n", 100, "/var/log/big.log") == 2048576
    # argv form: no shell, hostile paths stay inert.
    assert c.post_kwargs["command"] == ["stat", "-c", "%s", "/var/log/big.log"]


def test_file_size_plain_output() -> None:
    c = FakeClient(post_resp={"pid": 7},
                   get_resps=[{"exited": 1, "exitcode": 0, "out-data": "512\n"}])
    assert _qemu_file_size(c, "n", 100, "/x") == 512


def test_file_size_none_when_stat_missing() -> None:
    # exitcode 127: no `stat` binary in the guest -> caller falls back.
    c = FakeClient(post_resp={"pid": 7},
                   get_resps=[{"exited": 1, "exitcode": 127, "err-data": "nope"}])
    assert _qemu_file_size(c, "n", 100, "/x") is None


def test_file_size_none_when_agent_unavailable() -> None:
    c = FakeClient(post_resp={"error": "agent not running"})
    assert _qemu_file_size(c, "n", 100, "/x") is None


def test_file_size_none_on_missing_output() -> None:
    c = FakeClient(post_resp={"pid": 7},
                   get_resps=[{"exited": 1, "exitcode": 0}])
    assert _qemu_file_size(c, "n", 100, "/x") is None
