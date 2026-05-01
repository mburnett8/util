# Security Audit

## Problem

Our applications require verification of three key security controls:

1. **Content Security Policy (CSP)** — primary defense against XSS attacks
2. **Multi-Factor Authentication (MFA)** — protection against credential-based attacks on the Django admin
3. **GitHub Security Alerts** — Dependabot (dependency vulnerabilities) and Code Scanning (SAST) alerts

## Setup

```
npm install
```

Add a `.env` file in `security-audit/`:

```
GITHUB_TOKEN=<token>
```

## Running

```
npm run audit
```

Produces `results/security-audit-YYYY-MM-DD.md` with all three checks combined.

Individual scripts for targeted checks:

```
npm run audit:csp      # CSP headers on app and S3 endpoints
npm run audit:mfa      # MFA detection on app endpoints
npm run audit:github   # GitHub Dependabot and Code Scanning alerts
```

Requires Node 18+.

## Configuration

Each entry in `environments.json` represents one app:

```json
{
  "name": "koh-ksr",
  "repo": "koh_ksr_app",
  "environments": {
    "dev": {
      "app": "https://koh-ksr-dev-0-web.tribridge-amplifyhr.com/admin/login/",
      "s3": "https://koh-ksr-dev-0-fst-vib14r0b.s3.amazonaws.com/static/index.html",
      "csod": "https://kohler-pilot.csod.com/"
    },
    "prod": { ... }
  }
}
```

- `repo` — GitHub repo name in the `Intelladon-LLC` org; omit to skip GitHub alerts for this app
- `app` — Django admin login URL (checked for CSP, MFA)
- `s3` — S3 origin URL (checked for CSP only)
- `csod` — Cornerstone URL the app is embedded in (used to verify `frame-ancestors`)
- Use `"<placeholder>"` for any URL not yet known — those environments are skipped

## CSP checks (app endpoint)

- CSP header is present
- `default-src` or `script-src` is defined
- No `unsafe-inline` or `unsafe-eval` in script/default-src
- `frame-ancestors` is set and covers the CSOD host
- No bare wildcard (`*`) sources

## CSP checks (S3 endpoint)

- CSP header is present
- No `unsafe-inline`, `unsafe-eval`, or wildcard sources

## MFA check

Fetches the login page HTML and scans for OTP input fields, two-factor text, authenticator app references, verification code prompts, and TOTP references. Passive heuristic only — MFA implementations that surface the second factor after the first credential step will not be detected.

## GitHub checks

Fetches Dependabot and Code Scanning alerts filtered to `critical` and `high` severity. Code scanning alerts are split into FE (`/language:javascript-typescript`) and BE (`/language:python`, `/language:actions`) buckets based on the alert's category.
