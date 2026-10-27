# External software and dependencies

This document lists every piece of external software that SQL Inquisitor uses, explains why each one is needed, and describes how to install and configure it. The design goal is a small and auditable supply chain. There is exactly one runtime dependency, and the test environment needs one additional package. No database server, container runtime, message broker, browser driver or third-party security scanner is required.

## Summary of requirements

| Software | Version | Role | Required for |
| --- | --- | --- | --- |
| Python | 3.10 or newer | Interpreter and standard library | Running the tool and the tests |
| pip | Current version recommended | Python package installer | Installation |
| requests | 2.31 or newer, below 3 | HTTP client | All scanning and HTTP tests |
| pytest | 8.0 or newer | Test runner | Running the automated suite |
| pytest-cov | 5.0 or newer | Coverage integration | Optional coverage reports |
| ruff | 0.6 or newer | Linter | Optional development checks |
| Git | Any recent version | Source checkout | Optional, only for obtaining the source |
| curl | Any recent version | Manual probes | Optional, only for ad hoc debugging |

Everything else is part of the Python standard library: argument parsing, dataclasses, enums, logging, HTML parsing, URL handling, JSON and CSV-free reporting, timing, threading for the test server, SQLite for the lab database and the HTTP server itself.

## Python

SQL Inquisitor requires Python 3.10 or newer because the source uses modern type syntax such as `str | None`, the `dataclasses` and `enum` features from that era, and `importlib.metadata` for version reporting. Python 3.11 and 3.12 are the recommended versions and are the versions used in development. The package metadata declares `requires-python = ">=3.10"`, so pip refuses to install it on an older interpreter.

Most Linux distributions provide Python through their package manager. On Debian and Ubuntu, install `python3`, `python3-venv` and `python3-pip`. On Fedora and RHEL, install `python3` and `python3-pip`. On macOS, the system Python is usually too old or is reserved for the operating system, so install a current Python from the official installer, Homebrew or pyenv. On Windows, use the official installer from python.org and enable the option that adds Python to the `PATH`.

Verify the interpreter before you install anything.

```bash
python3 --version
python3 -c "import sys; print(sys.executable)"
```

A virtual environment keeps the project dependencies separate from the system interpreter. It is strongly recommended on every platform.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
```

On Windows, activate with `.venv\Scripts\activate` in Command Prompt or PowerShell. Once the environment is active, `python3` and `pip` refer to the virtual environment. No system-wide configuration file is needed.

## requests

`requests` is the only runtime dependency. It provides the HTTP session, connection pooling, TLS verification, redirect handling, proxy support, streaming responses and header management that the scanner needs. The package metadata pins it to `requests>=2.31,<3`, which allows security and bug-fix releases while avoiding a surprise major-version change.

Install it as part of the package.

```bash
python3 -m pip install -e .
```

Or install the exact runtime dependency on its own when you want to inspect the environment.

```bash
python3 -m pip install "requests>=2.31,<3"
```

No configuration file is required. The scanner builds a `requests.Session`, enables TLS verification by default, sets a configurable timeout and connection timeout, and disables retries that would defeat the request budget. Two behaviours are worth knowing. Proxy environment variables are ignored unless `--trust-env` is passed, and the proxy can also be set explicitly with `--proxy`. TLS verification can be disabled with `--insecure` for a controlled lab, but this should never be used against a real target.

If your organisation uses a private certificate authority, point `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` at the CA bundle and leave verification enabled. If you use a proxy, set `--proxy http://proxy.example:8080` or `--proxy socks5://proxy.example:1080`; SOCKS support requires the optional `requests[socks]` extra and the `PySocks` package, which is not installed by default. Keep the dependency surface small: install SOCKS support only if the engagement requires it.

The `requests` release notes and security advisories are published by the Requests project. Upgrade regularly with `python3 -m pip install --upgrade "requests>=2.31,<3"`.

## pytest

`pytest` is a development dependency, not a runtime dependency. It discovers the tests in `tests/`, provides fixtures, parametrization, assertions with detailed diffs, markers and the `caplog`, `monkeypatch` and `tmp_path` helpers that the suite uses. The project declares `pytest>=8.0` in the `dev` extra.

Install the development extras.

```bash
python3 -m pip install -e ".[dev]"
```

Or install pytest directly.

```bash
python3 -m pip install "pytest>=8.0"
```

No pytest plugin is mandatory. The suite relies on the configuration in `pyproject.toml`, which sets the source path, the test path, the default options and the registered markers. Run the suite from the repository root so that this configuration is discovered.

```bash
python3 -m pytest -q
```

## pytest-cov

`pytest-cov` is optional. It integrates coverage measurement into pytest and is declared in the `dev` extra as `pytest-cov>=5.0`. Install it with the development extras or on its own.

```bash
python3 -m pip install "pytest-cov>=5.0"
python3 -m pytest -q --cov=src --cov-report=term-missing
```

Coverage configuration lives in the `[tool.coverage.run]` and `[tool.coverage.report]` sections of `pyproject.toml`. No external coverage service is required. If you upload reports to a service, that service becomes an additional dependency and a data-sharing decision that this project does not make for you.

## ruff

`ruff` is an optional development linter. It is declared in the `dev` extra as `ruff>=0.6` and configured in `pyproject.toml` with a line length of 100 characters, a Python 3.10 target and the `E`, `F`, `W`, `I`, `B` and `UP` rule families. It is not imported at runtime and it is not needed to use the scanner.

Install it with the development extras and run it from the repository root.

```bash
python3 -m pip install -e ".[dev]"
python3 -m ruff check src tests
```

The `make lint` target runs the same command. Ruff has no configuration file beyond `pyproject.toml` and no service dependency. If you do not want to install it, the test suite and the scanner work without it; the CI workflow installs the development extras so that the lint step runs on every push.

## Git

Git is only needed to clone or update the source. It is not imported and it is not required at runtime. Install it from your operating system package manager or from git-scm.com. A source archive works equally well if you do not want to install Git.

## curl

`curl` is optional and is only useful for manual debugging of a lab endpoint or for checking connectivity before a scan. It is not used by the tool or by the test suite. Any HTTP client can replace it, including a browser or a short Python snippet with `requests`.

## What is deliberately not required

SQL Inquisitor does not wrap, import or invoke sqlmap. It does not need sqlmap, Burp Suite, OWASP ZAP, Nikto, Nmap, Metasploit or any other penetration testing framework. Its detection logic is implemented in this repository so that every request is visible and every decision is testable. If you already use sqlmap, keep using it for exploitation and data extraction if your engagement allows it; SQL Inquisitor is a focused detector with a different, read-only scope.

SQL Inquisitor requires no external database. The scanner talks only to the target over HTTP. The test suite needs no external database either, because the lab server creates an in-memory SQLite database through the Python standard library for every request. You do not need PostgreSQL, MySQL, MariaDB, Microsoft SQL Server, Oracle or a database driver. The scanner recognises the error signatures of those engines in HTTP responses, which requires no client library and no connection.

No Docker, Podman, Kubernetes, Vagrant or virtual machine is required. The lab server is a normal Python process that binds to an ephemeral loopback port. No Redis, RabbitMQ, Elasticsearch, Prometheus or other service is used. No browser automation, Selenium, Playwright or headless Chrome is used, because the crawler parses HTML with the standard library. No JavaScript runtime is needed.

## Operating system packages

On Linux, the only common system-level prerequisite is a working Python installation with the `venv` and `pip` modules. TLS verification uses the CA bundle that ships with `requests` through `certifi`, so a system CA package is normally not required, but keeping `ca-certificates` installed is still good practice for other tools.

If you build the project into a wheel or a source distribution, `setuptools>=68` is required by the build system. Pip installs it automatically in an isolated build environment. No compiler is needed because the project is pure Python.

On macOS, the official Python installer includes the required modules. On Windows, the official installer includes pip and the standard library; the only common issue is a `PATH` that does not include the Python scripts directory, which prevents the `sql-inquisitor` command from being found. Run `python3 src/cli.py` from the source tree or add the scripts directory to `PATH` if that happens.

## Installation from a clean checkout

The complete sequence for a clean development environment is shown below. It installs the runtime dependency, the command-line entry point and the test tools.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
sql-inquisitor --version
python3 -m pytest -q
```

If you only want to run the tool, install it without the development extras.

```bash
python3 -m pip install .
sql-inquisitor --help
```

If you do not want to install the package at all, run it from the source tree. Running `src/cli.py` as a script puts `src/` on the import path automatically; `pytest` does the same through `pythonpath = ["src"]`.

```bash
python3 src/cli.py --help
PYTHONPATH=src python3 -m pytest -q
```

## Verifying and updating

Check the installed versions when you report a problem.

```bash
python3 --version
python3 -m pip show requests pytest pytest-cov
sql-inquisitor --version
```

Update the development environment with pip. Review the release notes before a major upgrade, especially for `requests`, because a new major version may change redirect or TLS defaults.

```bash
python3 -m pip install --upgrade "requests>=2.31,<3" "pytest>=8.0" "pytest-cov>=5.0"
```

## Air-gapped and restricted environments

The project has no network dependency at runtime beyond the target itself. For an air-gapped machine, build a wheel and its dependencies on a connected machine and copy them across, then install from the local files.

```bash
python3 -m pip download --dest wheels -e ".[dev]"
python3 -m pip install --no-index --find-links wheels -e ".[dev]"
```

If your policy forbids installing `requests`, the tool cannot run, because the HTTP client is a deliberate dependency rather than an optional convenience. Do not vendor a modified copy of `requests` into the repository. A standard, auditable dependency is safer than an unmaintained fork.

## A note on supply-chain hygiene

Install from the official Python Package Index or from a trusted internal mirror, use a virtual environment, and pin versions in CI when reproducibility matters. Review the dependency list before adding a package. The project intentionally keeps the runtime list at one entry so that a security review can focus on the scanner's own logic and on `requests`, rather than on a large transitive dependency tree.

The only transitive runtime dependencies come from `requests`: `urllib3`, `certifi`, `charset-normalizer` and `idna`, plus their own small dependencies. They are well-known libraries maintained by the Python community. No telemetry, analytics or update service is contacted by SQL Inquisitor.

## Quick reference

Install the tool with `python3 -m pip install .`. Install the test tools with `python3 -m pip install -e ".[dev]"`. Run the tests with `python3 -m pytest -q`. The runtime dependency is `requests`; the test dependency is `pytest`; coverage is optional through `pytest-cov`. There is no external database, no Docker and no sqlmap. Python 3.10 or newer is the only platform requirement.
