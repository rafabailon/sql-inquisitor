"""Shared pytest fixtures for the SQL Inquisitor test suite."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from target_server import create_server  # noqa: E402

from config import ScanConfig  # noqa: E402
from engine import Scanner  # noqa: E402
from models import ALL_TECHNIQUES  # noqa: E402


@pytest.fixture(scope="session")
def lab():
    """Start the deliberately vulnerable lab on an ephemeral localhost port."""
    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    base_url = f"http://{host}:{port}"
    try:
        yield SimpleNamespace(base_url=base_url, server=server, state=server.state)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def config_factory(lab):
    """Build a fast, authorized scan configuration against the lab server."""

    def factory(path: str = "/clean?q=test", **overrides):
        values = {
            "target": lab.base_url + path,
            "authorized": True,
            "techniques": ALL_TECHNIQUES,
            "crawl": False,
            "delay": 0.0,
            "timeout": 5.0,
            "connect_timeout": 2.0,
            "max_retries": 0,
        }
        values.update(overrides)
        return ScanConfig(**values)

    return factory


@pytest.fixture
def run_scan():
    """Run a scanner to completion and return its result."""

    def runner(config: ScanConfig, explicit_points=None):
        return Scanner(config, explicit_points=explicit_points).scan()

    return runner
