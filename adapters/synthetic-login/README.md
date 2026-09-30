# Synthetic adapter 1.0.0

This adapter is restricted to the administrator-configured `http://127.0.0.1:<port>` fixture. It accepts no agent-provided URLs, selectors, scripts, screenshots, storage requests, tracing options or browser debugging controls.

The reviewed flow is `/login` → POST `/password` → `/totp` → POST `/otp` → `/profile`, using `acct_synthetic`, password plus TOTP, and the `synthetic_read_profile` action and observation profiles. Every typed input and submission checks the top-level origin, main-frame identity, route, form action/method, account, authentication step and input type. Frames, new tabs, external destinations and additional routes are refused. Authentication completes only after the expected account is independently observed on the profile route and login/security-interaction fields are absent.

The only post-login operation is `synthetic.read_profile`. Its result is a newly constructed fixed metadata object; arbitrary page text and browser state are never copied into observations. Each factor submits once. Ambiguous delivery quarantines the worker and returns `OUTCOME_UNKNOWN`.

`site.ts` intentionally contains synthetic attack cases and fixed test credential validation. It is not a real service adapter. Chromium tests exercise origin redirects, an external credential frame, a wrong authenticated account, account recovery, unexpected second-factor requirements, concurrency and uncertain delivery. They do not prove production OS/process isolation, real service compatibility, or device biometric behavior.
