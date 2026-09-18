---
name: Cross-site scripting (XSS)
category: injection
keywords: [xss, cross-site scripting, reflected, stored, dom, javascript, script, html, sanitization, encoding, csp, injection]
---
User input is reflected into a page without proper output encoding, letting an attacker run script in a victim's browser session. Impact ranges from session theft to full account takeover.

## Where to look
- Any value echoed back into HTML: search terms, error messages, profile fields, URL fragments.
- Stored surfaces: comments, usernames, support tickets, filenames rendered later.
- DOM sinks in client JS: `innerHTML`, `document.write`, `eval`, framework `dangerouslySetInnerHTML`.

## How to detect (tools + signals)
- Inject a unique benign marker and grep the response to see where and how it is reflected (attribute, tag body, script context, URL).
- Confirm the marker renders unencoded — `<`, `>`, `"` surviving into HTML is the signal, not the alert box.
- Map DOM flows with the browser devtools / DOMInvader; automate reflection discovery with `dalfox`, `nuclei`, or Burp.

## How to confirm
- Demonstrate script execution with a harmless proof (e.g. a console log or a benign DNS/HTTP callback to your own listener) — never target real users.
- Note the exact context and the encoding that failed, so remediation is precise.

## Common variations
- Reflected, stored, and DOM-based; mutation (mXSS) via HTML sanitizer quirks.
- Blind XSS in admin dashboards — use an out-of-band collector you control.
- Check for a Content-Security-Policy and whether it actually blocks the context you found.
