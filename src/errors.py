"""Exception hierarchy used across SQL Inquisitor."""

from __future__ import annotations


class SQLInquisitorError(Exception):
    """Base class for every error raised deliberately by the package."""


class ConfigError(SQLInquisitorError):
    """The user supplied an invalid configuration value."""


class AuthorizationError(SQLInquisitorError):
    """The operator did not confirm that they are allowed to test the target."""


class ScopeError(SQLInquisitorError):
    """The target or a discovered URL falls outside the authorized scope."""


class RequestBudgetExceeded(SQLInquisitorError):
    """The configured maximum number of HTTP requests was reached."""


class TargetUnreachableError(SQLInquisitorError):
    """The seed URL could not be fetched at all."""
