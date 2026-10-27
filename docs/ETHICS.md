# Ethics and authorized use

SQL Inquisitor is an active security testing tool. It sends requests that are designed to provoke database errors, change the logical result of a query and, for the time-based technique, make the database wait. Those requests are harmless only when they reach a system that you are authorized to test and when the surrounding rules of engagement allow them. The ethical guardrails in the tool exist to make accidental misuse difficult, but they cannot replace your own judgement, your contract and the law.

## Authorization comes first

Obtain explicit written authorization before the first request. A verbal approval, a public bug bounty scope page or an implicit assumption is not enough unless your engagement explicitly says so and you have recorded the scope. The authorization should identify the target hosts, the allowed time window, the permitted techniques, the person who can approve emergency stops and the reporting channel for findings.

The tool enforces a deliberate acknowledgement. Non-interactive use requires the `--authorized` flag. Interactive use without the flag prints a warning and asks the operator to type the exact phrase `I HAVE AUTHORIZATION`. Any other phrase, an empty answer, end of input or a non-interactive stdin causes the process to exit with status 3 before a request is sent. The flag is an acknowledgement, not a permission system. It records that a human decided that authorization exists.

The dry run is exempt from the authorization prompt because it sends no traffic. It still validates the target and prints the plan, which makes it the correct first step when you are preparing a change window.

```bash
sql-inquisitor "https://staging.example.test/search?q=test" --authorized --dry-run
```

## Stay inside the agreed scope

The scope guard is checked before the seed request, before every crawled link and before every form action. A target host must match the target host or an explicit `--scope` pattern. Wildcards match the apex domain and its subdomains, not look-alike suffixes such as `example.test.evil.example`. The `--cross-origin` option relaxes the same-origin rule for crawling but never relaxes the scope requirement.

Set the scope as narrowly as the engagement allows. Prefer a host name over a wide wildcard, prefer a staging environment over production, and exclude logout, delete, payment, administrative and destructive workflow URLs with `--exclude`. Respect `robots.txt` unless the engagement explicitly permits otherwise; the tool obeys it by default and `--no-robots` is an operator decision that should be documented.

Scope is not only a host list. It also includes the time window, the maximum request rate, the maximum number of requests and the techniques that the client approved. An authorized host tested outside the agreed window, at an abusive rate or with a technique the client excluded is still out of scope in practice.

## Cloud metadata and internal addresses

Cloud instance metadata services expose credentials and configuration, and they are a classic target for server-side request forgery. SQL Inquisitor always denies metadata host names such as `metadata.google.internal` and the common link-local metadata address. It also denies link-local, multicast, unspecified and reserved addresses, even when a scope pattern would otherwise match them. The denial is unconditional and cannot be disabled by a command-line flag.

Do not try to reach metadata endpoints by encoding the address, using a redirect, or pointing the scanner at an internal proxy. The crawler validates discovered links and form actions against the scope, but automatic HTTP redirects are followed by the HTTP client and the final URL is not revalidated; treat a redirect to an internal or metadata address as a potential SSRF finding and do not follow it manually.

## Read-only by construction

The payload catalogue contains only read-only constructs: SELECT statements, boolean expressions, error expressions, UNION SELECT probes and controlled delay functions. It contains no INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE or CREATE statement, no file write, no command execution and no privilege change. The stacked-query detector appends a second SELECT that references a random, non-existent table name; the resulting error proves execution without modifying data. The automated suite asserts that no destructive keyword appears in any generated payload.

Read-only does not mean zero impact. A malformed query can still consume database CPU, fill an error log, trip an alarm or trigger a web application firewall. A delay payload can hold a worker for the requested delay, and repeated probes can add load. Use a conservative request rate on production systems, keep the time delay small, and watch for HTTP 429, 503 and block pages.

## Rate, budget and blocking behaviour

The default delay between requests is intentionally conservative. Increase `--delay` on production systems and lower `--max-requests` to the smallest budget that still gives useful coverage. The client applies a monotonic-clock throttle and adds a penalty after HTTP 429 or 503, honouring `Retry-After` when the server provides it. The engine stops the scan after a bounded number of blocked responses instead of trying to push through.

SQL Inquisitor observes web application firewalls but does not attempt to evade them. It does not rotate user agents for evasion, spoof source addresses, solve challenges, fragment payloads specifically to defeat a filter, or retry a blocked request until it succeeds. If a target blocks the scan, stop and discuss the engagement with the client. A WAF block is a result to report, not an obstacle to defeat.

## No exploitation and no data extraction

The tool confirms the existence of injection classes. It does not extract rows, enumerate schemas, dump credentials, bypass authentication, upload files, execute commands or establish persistence. Evidence is limited to the behaviour needed for confirmation, such as a differential error signature, a boolean response split, a controlled UNION marker, a table-name error from a stacked statement or a measured delay.

If a finding is confirmed, stop escalating. Do not use the injection to read data that is outside the minimum needed to demonstrate impact. In many engagements the client will ask for a proof of concept that shows the vulnerable parameter, the payload and the observed difference; that is usually sufficient. Any deeper exploitation requires a separate written approval and a clear data-handling plan.

## Handle evidence and secrets carefully

Reports can contain URLs, parameter names, payloads, response snippets and timing data. They can also reveal internal host names and application structure. Treat reports as confidential client material. Store them in an access-controlled location, share them only with the named contacts and delete them according to the retention policy.

The public configuration embedded in reports redacts header values, cookie values and proxy credentials. It lists names so that the client can reproduce the request shape without exposing session tokens. Even so, review a report before sending it. A response snippet can contain personal data, a stack trace can contain a file path, and a URL can contain a token in a query string. Remove or mask anything that is not necessary for the finding.

Do not paste live session cookies, bearer tokens or production credentials into a ticket, a chat, an issue tracker or an example command. Use test accounts created for the engagement and revoke them afterwards.

## Legal and contractual context

Computer misuse, privacy and data protection laws differ by jurisdiction. Authorization from the system owner is necessary but it may not be sufficient: a hosting provider, a payment processor or a third-party API may have separate terms. A bug bounty program may prohibit automated scanning, may limit the techniques that are allowed or may require a specific rate. Read the program rules before you run the tool.

If you discover a vulnerability in a system that you do not own and have no authorization to test, stop and use the vendor's security contact or a coordinated disclosure channel. Do not verify the issue on a live system without permission. Do not publish details before the owner has had a reasonable opportunity to remediate.

## A practical pre-scan checklist

Confirm that written authorization exists and names the target, window and techniques. Confirm that the target URL resolves to the authorized host and not to a shared edge or a third-party service. Record the scope patterns and the exclusions in the engagement notes. Choose a conservative delay and request budget. Run `--dry-run` and review the normalized target and selected techniques. Start with a small technique subset on a single endpoint. Watch the target's error rate and blocking behaviour. Stop immediately if you see unexpected impact, and report it.

After the scan, review the findings for false positives, remove secrets from the evidence, deliver the report through the agreed channel, and keep the raw output only as long as the contract requires. If the client asks for a retest, use the same scope and rate limits and wait until the remediation window is agreed.

## Responsible disclosure

Give the owner a private, actionable report: affected endpoint, parameter, technique, payload class, evidence, impact, reproduction steps and remediation guidance. Provide a reasonable remediation window before public discussion. Do not include unnecessary personal data or credentials. If the owner is unresponsive, follow the disclosure policy that applies to the engagement or the jurisdiction rather than publishing unilaterally.

SQL Inquisitor is a tool for authorized defenders. Use it to find and fix injection before an attacker does, and treat every target as someone else's production system until your authorization says otherwise.
