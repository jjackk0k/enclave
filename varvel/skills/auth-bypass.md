---
name: Authentication bypass
category: auth
keywords: [auth, authentication, bypass, login, password, session, credential, cookie, mfa, otp, lockout, reset, remember]
---
Flaws that let an attacker reach an authenticated state without valid credentials, or hold a session longer than they should. Test only against accounts and systems you are authorized to.

## Where to look
- Login, "remember me", password-reset, and MFA/OTP flows; SSO/OAuth callbacks.
- Session cookies and tokens: how they are issued, scoped, rotated, and invalidated on logout.
- Hidden/alternate entry points: `/admin`, API routes that skip the web login, mobile endpoints.

## How to detect (tools + signals)
- Force-browse to post-login URLs without a session — does the app serve them (a missing access check)?
- Reset-flow logic: predictable tokens, host-header poisoning of the reset link, response that leaks the token or a user-existence oracle.
- MFA gaps: is the second factor enforced server-side on every step, or can the final request be replayed skipping it?
- Rate-limiting/lockout: measure whether repeated attempts are throttled (authorized, capped attempts with `ffuf`/Burp Intruder against a test account).

## How to confirm
- Demonstrate reaching an authenticated resource or another user's session without their credentials, using a benign account you control on both sides.
- Capture the request/response pair that proves the missing check.

## Common variations
- Session fixation, insecure "remember me" tokens, JWT weaknesses (see jwt-attacks), OAuth `redirect_uri`/state flaws, default or seeded credentials.
