# Detection

SQL Inquisitor tests five SQL injection classes. Each class has its own payload family, confirmation rule and failure mode. The scanner intentionally favours a small number of high-quality probes over exhaustive fuzzing. This document explains what each detector sends, how it decides that a finding is real, which database engines it recognizes and where its limits lie.

## Shared principles

Every detector receives an injection point and a baseline response. The baseline is the response for the original parameter value, cached by method, URL, query parameters, body data and multipart fields. The scanner treats transport failures and blocked responses as stop signals rather than as negative evidence. A WAF block is never interpreted as proof of vulnerability.

A detector returns data only after two observations. The first observation produces a candidate; the second observation must reproduce the same mechanism. This differential rule is the core defence against reflections, random page content, cached responses and coincidental errors. The engine also deduplicates findings by technique, method, URL and parameter.

Payloads are read-only. They select data, compare expressions, raise controlled errors or request a delay. They never insert, update, delete, drop, alter, truncate or create database objects. The test suite enforces this invariant by scanning every generated payload for destructive keywords.

## Error-based injection

The error detector sends syntax-breaking values such as a single quote, a double quote, a backslash, a closing parenthesis, a comment opener and combinations of these. It also sends numeric probes for numeric-looking parameters. The goal is to make the surrounding SQL statement invalid and to observe a database error that was not present in the baseline.

The decision is differential. `find_dbms_errors` scans a response for known error patterns and returns a set of keys formed from the DBMS family and the pattern. `new_sql_errors` returns the keys present in the probe response but absent from the baseline. If no new key appears, the probe is ignored. If a new key appears, the detector sends the same payload again. The finding is confirmed only if the same new key reproduces. This prevents a page that always contains documentation text such as `Warning: mysql_query() failed` from becoming a false positive, because the signature already exists in the baseline.

The detector stops at the first reproducible signature and records the DBMS, the pattern, a short snippet around the match and the payload context. Confidence is high because a database error that appears only after injection and reproduces is strong evidence of string concatenation. The severity is critical.

The signature table covers MySQL and MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, Microsoft Access, IBM DB2, Firebird and generic PDO, SQLSTATE, JDBC and ODBC messages. It includes syntax errors, unclosed quotation marks, unknown columns, missing tables, driver exceptions and type conversion failures. New engines can be added by extending `DBMS_SIGNATURES`.

Error-based detection can miss injection when the application swallows database errors, returns a generic error page or runs in production mode with detailed errors disabled. It can also miss injection in a context where the probes do not break syntax. In those cases boolean-based, time-based or UNION-based detection may still succeed.

## Boolean-based blind injection

Boolean-based detection is used when the application does not disclose errors but changes its response depending on whether a condition is true. The detector sends paired true and false conditions in several syntactic contexts: single quote, double quote, parenthesis and numeric.

A typical pair for a string parameter is `test' AND '1'='1'-- -` and `test' AND '1'='2'-- -`. The first condition is true and should produce the normal result set; the second is false and should produce an empty or different result set. Pairs using `OR`, numeric comparisons, `LIKE`, hash comments, block comments and wildcard-preserving forms are also generated. Pairs are ordered from the most common contexts to the least common, so a typical vulnerable point succeeds within two or three pairs.

For each pair, the detector verifies that both responses have the baseline status code, that neither response introduces a new SQL error and that neither response is blocked. It removes the reflected payload from each body, including URL-encoded and HTML-escaped variants, and normalizes volatile tokens such as UUIDs, ISO timestamps, long hexadecimal strings, base64 blobs, epoch values and CSRF or nonce fields. It then computes text similarity between the baseline and each response.

The pair is a candidate when the response on the expected side resembles the baseline and the response on the other side differs. The detector accepts an exact normalized match combined with a true/false difference, or a strong similarity separation, or a conservative threshold-based separation. The default thresholds require the baseline-like score to be at least 0.97, the other score to be at most 0.90, a gap of at least 0.06 and a true/false similarity of at most 0.90. A different pair can also confirm with a score of at least 0.995 against the baseline, at most 0.97 for the other side, a gap of at least 0.01 and a pair similarity of at most 0.98. Two independent pairs must pass. The severity is high and the confidence is high.

The baseline side can be true or false. For `AND` pairs the original value usually behaves like a true condition, so the true response is baseline-like. For `OR 1=1` pairs the original value usually behaves like false, so the false response is baseline-like. The pair dataclass records which side is expected to match.

Normalization is essential on real applications. Without it, rotating CSRF tokens would make every response different and boolean detection would either fail or produce false positives. The normalization in `heuristics.py` replaces volatile values with stable placeholders before similarity is computed.

Boolean detection fails when the application returns byte-identical pages for true and false conditions, when a WAF blocks all condition syntax, when the response is binary or compressed in a way that defeats text comparison, or when the parameter is not used in a boolean context. It can also be slow on very large responses, although the similarity implementation switches to bounded shingling above 20,000 characters.

## Time-based blind injection

Time-based detection is the fallback when neither errors nor response differences are observable. It sends database-specific delay expressions and compares the response time with baseline timing samples.

The detector collects at least `time_samples` baseline timings for the original value. It then sends delay payloads for MySQL and MariaDB (`SLEEP`), PostgreSQL (`pg_sleep` and a stacked `pg_sleep`), Microsoft SQL Server (`WAITFOR DELAY`) and Oracle (`dbms_pipe.receive_message`). The first payload that produces a delay is followed by a confirmation payload with a shorter delay, typically 60 percent of the original, and the detector checks that the shorter delay is also present and proportionally faster.

The absolute delay rule compares the observed elapsed time against the baseline median plus a tolerance of 70 percent of the requested delay. It also requires at least 75 percent of the requested delay in absolute terms and adds a jitter margin based on the median absolute deviation of the baseline samples. The scaling rule then checks that the probe was delayed, that the shorter confirmation was delayed and that the difference between the two elapsed times is at least half of the difference between the requested delays. This two-point test rejects endpoints that are simply slow, cached or rate-limited, because a constant delay does not scale.

The detector reports the DBMS family of the payload, the baseline median in milliseconds, the probe duration, the confirmation duration, the requested delays and the baseline samples. Confidence is high and severity is high. The finding is not proof that the delay function executed in the exact statement the tester imagines; it is proof that the injected delay expression influenced database execution time.

Time detection is the slowest and noisiest technique. A remote target with jitter may need a delay of two to five seconds and more samples. A delay that exceeds the request timeout will time out before the payload completes, so `time_delay` must remain safely below `timeout`. The engine skips time detection on a point already confirmed by another technique unless `--thorough` is used. This is a deliberate performance and courtesy decision, not a claim that the other techniques are sufficient for every report.

## UNION-based injection

UNION-based detection tries to append a second result set to the original query. It is the most decisive technique because it can prove that the attacker controls the shape of the result set and can later extract data, although SQL Inquisitor stops at proof and does not extract data.

The detector generates a random numeric marker between ten million and ninety million. It builds an expression of the form `(marker-1)+1`, so the marker value itself never appears in the request. The database evaluates the expression to the marker. If the HTML reflects the request, it reflects the expression, not the result, so reflection cannot create a false positive. The detector also ensures that the marker is absent from the baseline body.

It then tries UNION contexts in order: numeric, single quote, double quote, parenthesis and the MySQL `FROM dual` variant. For each context it increases the column count from one to `max_union_columns` and sends a payload with the marker expression in the first column and `NULL` in the remaining columns. If the original query has a different number of columns, the database returns an error, which is expected and ignored. When the marker appears in a response that did not contain it at baseline, the detector sends the same payload again. A confirmed second appearance produces a finding with the context, column count and marker.

If the first phase sees any SQL error, the detector runs a second phase that first finds a column count for which an all-`NULL` UNION does not error, then places the marker expression in each column position in turn. This covers queries where the marker expression cannot be placed in the first column, for example because of type coercion or output formatting. The second phase is skipped when no SQL error was observed, which keeps the common case cheap.

UNION findings are critical and high confidence. The engine records the column count. UNION detection fails when the application does not display query results, when the result set is rendered as an image or binary document, when strict typing prevents the expression from appearing as text, or when a WAF blocks `UNION`. It can also be confused by an application that reflects the evaluated value from another source, but the random marker and the baseline exclusion make that unlikely.

## Stacked-query injection

Stacked-query detection tests whether the database driver executes more than one statement from a single parameter. It is a critical capability because stacked statements can, in principle, perform writes or administrative actions. SQL Inquisitor deliberately restricts itself to a read-only second statement that references a random table name, plus a division-by-zero fallback.

The detector creates a token such as `inq1a2b3c4d5e6f`. It sends payloads that close the original statement and append `SELECT * FROM token` in single-quote, double-quote, parenthesis and numeric contexts, followed by a comment. Because the table does not exist, a database that executes the second statement returns an error containing the token and a table-related phrase such as `no such table`, `doesn't exist`, `unknown table` or `invalid object name`. The detector requires both the token and a table-error marker in the same signature, then repeats the payload and requires the same evidence. This avoids the common false positive where a page reflects the token in a generic error message.

The division-by-zero fallback sends a second statement containing `SELECT 1/0`. If the database reports a reproducible division error, the detector reports a medium-confidence stacked-query finding. The fallback is useful on engines that do not disclose missing-table errors but do disclose arithmetic errors, but it is weaker evidence because some applications generate division errors for unrelated reasons. The table-token path is the preferred and high-confidence path.

Stacked-query detection fails when the driver disables multiple statements, which is common in hardened MySQL and PostgreSQL drivers, when the application uses a database account without permission to select from arbitrary names, or when errors are suppressed. A negative result does not prove that stacked queries are impossible, only that this scanner did not observe their effects.

## Database signatures

The signature table maps regular expressions to DBMS families. The order is MySQL and MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, Microsoft Access, IBM DB2, Firebird and generic SQL. The generic family catches PDO exceptions, SQLSTATE codes, generic JDBC exceptions, unclosed quotation marks and ODBC errors. The detector prefers a specific family over the generic family when both appear.

Snippets are extracted with a radius of 90 characters around the match, whitespace-collapsed and capped at 280 characters. This gives the report useful context without copying an entire error page. Signature keys combine the DBMS and the pattern text, so two different patterns for the same DBMS are treated as different evidence, while the same pattern in the baseline and the probe is treated as pre-existing noise.

## False-positive controls

Every technique uses at least one control. Error-based detection compares against the baseline signature set and requires reproduction. Boolean-based detection removes reflections, normalizes volatile tokens, requires two independent pairs and rejects responses with new SQL errors. Time-based detection measures baseline jitter and requires proportional scaling. UNION-based detection uses an evaluated random marker absent from the request and confirms it twice. Stacked detection requires the generated table token and a table-error phrase in the same signature and confirms it twice.

The engine adds two more controls. It records status codes and response lengths with each finding so a reviewer can inspect the evidence. It stops after 25 blocked requests, which prevents a scan from mistaking a WAF block page for a vulnerable response and prevents accidental abusive traffic.

## Severity model

Error-based, UNION-based and stacked-query findings are critical because they demonstrate direct control over SQL syntax or result sets. Boolean-based and time-based blind findings are high because they demonstrate injectable logic without necessarily exposing result data. The model is intentionally conservative and is defined once in `models.py`; reporters do not assign severity independently.

## Limitations and non-goals

SQL Inquisitor does not extract data, dump schemas, crack hashes, bypass authentication, upload files, execute operating system commands, escalate privileges or establish persistence. It does not test second-order injection, stored injection, JSON or XML body injection, GraphQL injection, ORM-specific injection or NoSQL injection. It does not attempt WAF evasion. It does not prove the absence of SQL injection, and a clean report should be read as "no finding was confirmed under this configuration", not as a certification.

Coverage depends on discovery. A parameter hidden behind JavaScript, a form protected by a CAPTCHA, an API endpoint without links, or a route that requires a specific sequence of requests will not be found by the crawler. For those cases, supply explicit `--param` or `--data` arguments or extend the crawler. Coverage also depends on the request context: a scanner cannot see a vulnerability in a parameter that the application ignores, and it cannot see a vulnerability in a database path that the target never executes.
