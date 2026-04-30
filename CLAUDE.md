# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Structure

`util` is a collection of standalone security utilities. Each subdirectory is an independent tool with its own `package.json` and `CLAUDE.md`.

| Directory | Purpose |
|---|---|
| `security-audit/` | Audits deployed apps and GitHub repos for security posture (CSP, MFA, Dependabot, Code Scanning) |

## Environment

Each utility manages its own `.env`. For `security-audit/`, create `security-audit/.env`:

```
GITHUB_TOKEN=<token>
```

## Linting

The project uses SonarQube rules surfaced via IDE diagnostics. Apply suggestions with judgment — not every rule produces better code. Fix issues that genuinely improve readability or correctness; skip mechanical compliance that adds noise without benefit.
