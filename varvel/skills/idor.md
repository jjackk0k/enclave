---
name: Insecure direct object reference (IDOR)
category: access-control
keywords: [idor, insecure direct object reference, object reference, authorization, ownership, tenant, horizontal, enumeration, identifier, account]
---
The application exposes a reference to an object (a record, file, or account) and fails to check that the current user is allowed to access that specific object — so changing the reference reaches someone else's data.

## Where to look
- Numeric or UUID identifiers in URLs, JSON bodies, and headers: `/invoice/1042`, `?account=…`, `orderId`, `fileId`.
- Export/download/print endpoints and API routes that fetch "my" resource by id.
- Multi-tenant apps where a tenant id is passed by the client.

## How to detect (tools + signals)
- Authenticate as user A, capture a request for A's object, then replay it as user B (or with no session) and swap the identifier — access to A's data is the signal.
- Increment/decrement sequential ids; for UUIDs, look for leaked ids elsewhere (listings, emails, referrers).
- Compare authorization behavior across roles with Burp's Autorize/AuthMatrix extension.

## How to confirm
- Show one authorized test account retrieving or acting on a second authorized test account's object, and record both the request and the returned foreign data as evidence.
- Keep it to accounts you own — read is enough to prove impact; do not alter real records.

## Common variations
- Horizontal (peer user's data) vs vertical (elevate to admin — see broken-access-control).
- Mass-assignment cousins where a client-supplied field (owner id, role) is trusted on write.
