---
name: Server-side request forgery (SSRF)
category: injection
keywords: [ssrf, request forgery, url, webhook, fetch, proxy, callback, metadata, imds, internal, redirect, import]
---
The server can be coerced into making requests to a location the attacker chooses — reaching internal services, cloud metadata, or the loopback interface it should never expose.

## Where to look
- Features that take a URL: webhooks, "import from URL", link previews, PDF/screenshot renderers, avatar-by-URL, XML/SVG parsers.
- Parameters like `url=`, `next=`, `dest=`, `feed=`, `callback=`, `image=`.
- Anything that fetches, proxies, or follows redirects on the server side.

## How to detect (tools + signals)
- Point the parameter at a listener you control (an out-of-band interaction server / your Enclave collector) and watch for an inbound hit — the DNS/HTTP callback is the signal.
- Compare timing and error text for internal vs external hosts to infer blind SSRF.
- Use Burp Collaborator / `interactsh` for out-of-band confirmation; `nuclei` ssrf templates for coverage.

## How to confirm
- Show the server reached an address the client cannot — loopback, an RFC1918 internal host, or the cloud metadata endpoint (169.254.169.254) — with a benign read.
- Capture the response or the OOB callback as evidence; do not pull real credentials from metadata beyond what proves the reach.

## Common variations
- Blind SSRF (no response body — rely on OOB) vs full-response SSRF.
- Filter bypasses: redirects, alternate IP encodings, DNS rebinding, `[::]`/`0.0.0.0`.
- Gopher/file/dict schemes to reach non-HTTP internal services; check what schemes the fetcher allows.
