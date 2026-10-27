"""Database error signatures used for error-based and stacked-query detection."""

from __future__ import annotations

import re
from dataclasses import dataclass

DBMS_SIGNATURES: dict[str, tuple[str, ...]] = {
    "MySQL/MariaDB": (
        r"You have an error in your SQL syntax",
        r"Warning\s*:\s*mysql_",
        r"\bMySql(?:Exception|Client)\b",
        r"check the manual that corresponds to your (?:MySQL|MariaDB) server version",
        r"com\.mysql\.jdbc\.exceptions\.jdbc4?\.\w+",
        r"MariaDB server version",
        r"Unknown column '[^']+' in '(?:field list|order clause|where clause)'",
        r"Table '[^']+' doesn't exist",
        r"Column count doesn't match value count",
        r"Truncated incorrect (?:DOUBLE|INTEGER|DECIMAL) value",
    ),
    "PostgreSQL": (
        r"PostgreSQL\b.{0,40}\bERROR\b",
        r"\bpg_query\(\)",
        r"Warning\s*:\s*pg_",
        r"ERROR:\s+syntax error at or near",
        r"ERROR:\s+unterminated quoted string",
        r"ERROR:\s+column \"[^\"]+\" does not exist",
        r"ERROR:\s+relation \"[^\"]+\" does not exist",
        r"\bPSQLException\b",
        r"current transaction is aborted",
        r"unterminated quoted string at or near",
    ),
    "Microsoft SQL Server": (
        r"Microsoft OLE DB Provider for SQL Server",
        r"ODBC SQL Server Driver",
        r"\bSqlException\b",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
        r"Conversion failed when converting",
        r"System\.Data\.SqlClient",
        r"Microsoft SQL Server\b.{0,80}\berror\b",
        r"Unclosed quotation mark before the character string",
        r"Invalid object name",
        r"Invalid column name",
    ),
    "Oracle": (
        r"\bORA-\d{4,5}\b",
        r"Oracle error",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"java\.sql\.SQLSyntaxErrorException",
        r"ORA-00933",
        r"ORA-01756",
        r"ORA-00936",
    ),
    "SQLite": (
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"sqlite3\.(?:OperationalError|ProgrammingError|DatabaseError|IntegrityError|InterfaceError)",
        r"no such table:\s*[\w.]+",
        r"no such column:\s*[\w.]+",
        r"near \"[^\"]*\": syntax error",
        r"unrecognized token:\s*\"[^\"]*\"",
        r"incomplete input",
        r"SELECTs to the left and right of UNION do not have the same number of result columns",
        r"\bSQLITE_ERROR\b",
    ),
    "Microsoft Access": (
        r"Microsoft JET Database Engine",
        r"Syntax error in string in query expression",
        r"Syntax error \(missing operator\) in query expression",
    ),
    "IBM DB2": (
        r"DB2 SQL error:\s*SQLCODE",
        r"SQLCODE\s*=\s*-\d+",
    ),
    "Firebird": (
        r"Dynamic SQL Error",
        r"SQL error code = -\d+",
    ),
    "Generic SQL": (
        r"\bPDOException\b",
        r"\bSQLSTATE\[\w+\]",
        r"\bjava\.sql\.SQLException\b",
        r"unclosed quotation mark",
        r"ODBC Driver\b.{0,40}\berror\b",
    ),
}

_COMPILED: dict[str, tuple[re.Pattern[str], ...]] = {
    dbms: tuple(re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns)
    for dbms, patterns in DBMS_SIGNATURES.items()
}


@dataclass(frozen=True)
class DetectedError:
    dbms: str
    pattern: str
    snippet: str

    @property
    def key(self) -> str:
        return f"{self.dbms}:{self.pattern}"


def _snippet(text: str, start: int, end: int, radius: int = 90) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    excerpt = re.sub(r"\s+", " ", text[left:right]).strip()
    if len(excerpt) > 280:
        excerpt = excerpt[:277] + "..."
    return excerpt


def find_dbms_errors(text: str, limit: int = 20) -> list[DetectedError]:
    """Return database error matches found in ``text``.

    The full body is scanned once per DBMS family. Duplicate signatures are collapsed while
    preserving the order in which the families appear in the table above.
    """
    if not text:
        return []
    found: list[DetectedError] = []
    seen: set[str] = set()
    for dbms, patterns in _COMPILED.items():
        for pattern in patterns:
            for match in pattern.finditer(text):
                key = f"{dbms}:{pattern.pattern}"
                if key in seen:
                    continue
                seen.add(key)
                found.append(
                    DetectedError(
                        dbms=dbms,
                        pattern=pattern.pattern,
                        snippet=_snippet(text, match.start(), match.end()),
                    )
                )
                if len(found) >= limit:
                    return found
    return found


def error_keys(text: str) -> set[str]:
    return {error.key for error in find_dbms_errors(text)}


def new_sql_errors(baseline_text: str, probe_text: str) -> list[DetectedError]:
    """Return errors in ``probe_text`` that were not already present in ``baseline_text``.

    This differential rule is what keeps a page that always prints the words "SQL error" from
    becoming a false positive.
    """
    baseline_keys = error_keys(baseline_text)
    return [error for error in find_dbms_errors(probe_text) if error.key not in baseline_keys]


def has_new_sql_error(baseline_text: str, probe_text: str) -> bool:
    return bool(new_sql_errors(baseline_text, probe_text))


def detect_dbms(text: str) -> str | None:
    errors = find_dbms_errors(text, limit=1)
    return errors[0].dbms if errors else None
