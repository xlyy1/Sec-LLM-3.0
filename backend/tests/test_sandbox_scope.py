"""Sandbox target guard: private/loopback/internal targets are rejected."""
from tools.shell import _candidate_hosts, _target_error


def test_private_ip_is_rejected():
    assert _target_error(["127.0.0.1"]) != ""
    assert _target_error(["192.168.1.10"]) != ""
    assert _target_error(["10.0.0.5"]) != ""


def test_internal_hostnames_are_rejected():
    assert _target_error(["host.docker.internal"]) != ""
    assert _target_error(["localhost"]) != ""


def test_url_host_extraction():
    assert _candidate_hosts(["-u", "http://127.0.0.1:8000/x"]) == ["127.0.0.1"]
    assert _candidate_hosts(["-u", "https://example.com/x"]) == ["example.com"]


def test_file_paths_are_not_targets():
    assert _candidate_hosts(["-w", "/tmp/wordlist.txt"]) == []
