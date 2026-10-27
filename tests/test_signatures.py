"""Database error signature tests."""

from __future__ import annotations

from signatures import (
    DBMS_SIGNATURES,
    detect_dbms,
    error_keys,
    find_dbms_errors,
    has_new_sql_error,
    new_sql_errors,
)


def test_signature_table_covers_expected_engines():
    expected = {
        "MySQL/MariaDB",
        "PostgreSQL",
        "Microsoft SQL Server",
        "Oracle",
        "SQLite",
        "Microsoft Access",
        "IBM DB2",
        "Firebird",
        "Generic SQL",
    }
    assert expected <= set(DBMS_SIGNATURES)


def test_find_mysql_error():
    errors = find_dbms_errors(
        "Warning: mysql_query() failed: You have an error in your SQL syntax near 'foo'"
    )
    assert errors
    assert errors[0].dbms == "MySQL/MariaDB"
    assert "You have an error in your SQL syntax" in errors[0].pattern
    assert "mysql" in errors[0].snippet.lower()


def test_find_sqlite_no_such_table_error():
    errors = find_dbms_errors("Database error: no such table: inq123abc")
    assert errors
    assert errors[0].dbms == "SQLite"
    assert "no such table" in errors[0].snippet


def test_find_postgres_error():
    errors = find_dbms_errors('ERROR: syntax error at or near "\'"')
    assert errors
    assert errors[0].dbms == "PostgreSQL"


def test_find_oracle_and_mssql_errors():
    oracle = find_dbms_errors("ORA-00933: SQL command not properly ended")
    mssql = find_dbms_errors("Microsoft OLE DB Provider for SQL Server error '80040e14'")
    assert oracle and oracle[0].dbms == "Oracle"
    assert mssql and mssql[0].dbms == "Microsoft SQL Server"


def test_no_errors_in_plain_text():
    assert find_dbms_errors("Welcome to the documentation") == []
    assert find_dbms_errors("") == []
    assert detect_dbms("Welcome") is None


def test_limit_is_respected():
    body = (
        "You have an error in your SQL syntax; "
        "pg_query() failed; ORA-00933; no such table: x; SQLSTATE[HY000]"
    )
    assert len(find_dbms_errors(body, limit=2)) == 2


def test_new_sql_errors_is_differential():
    baseline = "<p>Warning: mysql_query() failed is only a documentation example.</p>"
    probe = baseline + "<p>You have an error in your SQL syntax near 'x'</p>"
    errors = new_sql_errors(baseline, probe)
    assert errors
    assert all("You have an error" in error.snippet for error in errors)
    assert new_sql_errors(baseline, baseline) == []
    assert not has_new_sql_error(baseline, baseline)
    assert has_new_sql_error(baseline, probe)


def test_error_keys_are_stable():
    body = "no such table: inqabc"
    keys = error_keys(body)
    assert keys
    assert keys == error_keys(body)
    assert detect_dbms(body) == "SQLite"


def test_snippet_is_bounded_and_whitespace_normalized():
    body = "x" * 1000 + "   no such table: inqabc   " + "y" * 1000
    errors = find_dbms_errors(body)
    assert errors
    snippet = errors[0].snippet
    assert len(snippet) <= 280
    assert "\n" not in snippet
    assert "  " not in snippet
