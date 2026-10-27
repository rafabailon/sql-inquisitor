"""Documentation quality gates: presence, prose formatting and dependency claims."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC_FILES = [
    ROOT / "README.md",
    ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "docs" / "USAGE.md",
    ROOT / "docs" / "DETECTION.md",
    ROOT / "docs" / "TESTING.md",
    ROOT / "docs" / "ETHICS.md",
    ROOT / "docs" / "EXTERNAL_SOFTWARE.md",
]


@pytest.mark.parametrize("path", DOC_FILES, ids=lambda path: path.name)
def test_required_documentation_exists(path):
    assert path.is_file(), f"missing documentation file: {path}"
    assert path.read_text(encoding="utf-8").strip(), f"empty documentation file: {path}"


@pytest.mark.parametrize("path", DOC_FILES, ids=lambda path: path.name)
def test_markdown_has_no_leading_indentation(path):
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        assert not line.startswith((" ", "\t")), (
            f"{path.name}:{number} starts with indentation: {line!r}"
        )


def test_readme_introduces_the_project_and_authorization():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "SQL Inquisitor" in text
    assert "--authorized" in text
    assert "authorization" in text.lower()
    assert "pytest" in text


def test_documentation_describes_detection_techniques():
    text = (ROOT / "docs" / "DETECTION.md").read_text(encoding="utf-8")
    for phrase in (
        "error-based",
        "boolean-based blind",
        "time-based blind",
        "UNION-based",
        "stacked",
    ):
        assert phrase.lower() in text.lower()


def test_external_software_document_is_complete():
    text = (ROOT / "docs" / "EXTERNAL_SOFTWARE.md").read_text(encoding="utf-8")
    assert "Python" in text
    assert "requests" in text
    assert "pytest" in text
    assert "pip install" in text
    assert "sqlmap" in text.lower()
    assert "no external database" in text.lower()


def test_architecture_document_lists_modules():
    text = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    for module in (
        "config.py",
        "crawler.py",
        "http_client.py",
        "payloads.py",
        "engine.py",
        "reporting.py",
        "cli.py",
    ):
        assert module in text


def test_source_modules_live_directly_under_src():
    src = ROOT / "src"
    for module in ("cli.py", "config.py", "engine.py", "models.py", "version.py"):
        assert (src / module).is_file(), f"missing source module: src/{module}"
    assert (src / "detectors" / "base.py").is_file()
    nested = sorted(
        path.name
        for path in src.iterdir()
        if path.is_dir()
        and path.name not in {"detectors", "__pycache__"}
        and not path.name.startswith(".")
        and not path.name.endswith(".egg-info")
    )
    assert nested == [], f"unexpected nested source directories: {nested}"


def test_ethics_document_states_the_guardrails():
    text = (ROOT / "docs" / "ETHICS.md").read_text(encoding="utf-8")
    assert "I HAVE AUTHORIZATION" in text
    assert "scope" in text.lower()
    assert "metadata" in text.lower()
    assert "read-only" in text.lower()


def test_pyproject_declares_only_requests_as_runtime_dependency():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dependencies = ["requests>=2.31,<3"]' in text
    assert "[project.scripts]" in text
    assert 'sql-inquisitor = "cli:entrypoint"' in text


def test_license_exists_and_is_mit():
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in license_text
    assert "Permission is hereby granted" in license_text


def test_testing_document_lists_the_test_modules():
    text = (ROOT / "docs" / "TESTING.md").read_text(encoding="utf-8")
    for name in (
        "test_config.py",
        "test_payloads.py",
        "test_detectors.py",
        "test_engine.py",
        "test_cli.py",
        "test_lab_server.py",
    ):
        assert name in text
