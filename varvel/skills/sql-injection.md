---
name: SQL injection
category: injection
keywords: [sql, sqli, injection, login, database, query, orm, search, filter, sort, id, sqlmap]
---
Untrusted input reaches a SQL query so an attacker can alter its structure. High-impact and common on login, search, filter, sort, and any parameter that maps to a WHERE/ORDER BY clause. Authorized, in-scope testing only.

## Where to look
- Login and password-reset forms; search boxes; `?id=`, `?sort=`, `?filter=`, `?category=` query params.
- JSON/GraphQL fields, HTTP headers (User-Agent, X-Forwarded-For), and cookies that back a lookup.
- Anything that changes result counts or ordering — those map directly to SQL.

## How to detect (tools + signals)
- Send a syntax-breaking character (a single quote) and watch for a 500, a DB error string (ORA-, SQLSTATE, syntax near), or a changed response.
- Boolean test: compare a condition that is always-true vs always-false and look for a stable difference in the response body/length.
- Blind/time test: a conditional delay that only fires when injectable confirms no-visible-output cases.
- Automate coverage with `sqlmap` (authorized target list) and `nuclei` sqli templates; proxy through Burp/ZAP to diff responses.

## How to confirm
- Reproduce the boolean pair deterministically (true → data, false → empty) on the same parameter.
- For error-based, capture the exact DBMS error the payload provoked as evidence.
- Prefer the least-invasive proof (a version string via a read-only expression) over any data modification. Never DROP/UPDATE/DELETE on a client system.

## Common variations
- In-band (error/UNION), inferential (boolean/time-based blind), and out-of-band (DNS/HTTP) channels.
- Second-order: input stored then executed by a later query.
- ORM/NoSQL cousins — see the SSTI and injection playbooks for template/NoSQL operator abuse.
