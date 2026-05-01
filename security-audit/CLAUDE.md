# Security Audit — Claude Instructions

## Running the audits

The primary command runs all three checks and writes the combined report:

```
npm run audit          # runs audit.js → results/security-audit-YYYY-MM-DD.html
```

Individual scripts are available for targeted use:

```
node audit-csp.js              # CSP header checks (console output)
node audit-mfa.js              # MFA detection (console output)
node audit-github.js           # GitHub alerts → output/github/security_summary.md
node audit-github.js --cache   # regenerate GitHub report from cached JSON
```

Or via npm:

```
npm run audit:csp
npm run audit:mfa
npm run audit:github
```

Requires Node 18+. Run `npm install` once to install `dotenv` (required by `audit-github.js` and `audit.js`). The CSP and MFA scripts have no dependencies.

## Architecture

`audit.js` is the orchestrator. It imports `fetchCspData`, `fetchMfaData`, and `fetchGithubData` from the three individual scripts, runs them against the entries in `environments.json`, and builds a combined markdown report.

Each individual script is also a standalone CLI: it guards its top-level execution with `process.argv[1] === fileURLToPath(import.meta.url)`, so it runs its console output when invoked directly but exposes only the data function when imported.

## environments.json

Each entry in `environments.json` represents one app. To include GitHub security alert data in the combined report, the entry must have a `repo` field matching the GitHub repo name in the `Intelladon-LLC` org:

```json
{
  "name": "koh-ksr",
  "repo": "koh_ksr_app",
  "environments": {
    "prod": {
      "app": "https://...",
      "s3": "https://...",
      "csod": "https://..."
    }
  }
}
```

Entries without a `repo` field are skipped in the GitHub section. Use `"<placeholder>"` for any URL not yet known — those environments are skipped at runtime.

## GitHub Audit

`fetchGithubData` fetches Dependabot and Code Scanning alerts (critical and high severity only) for each repo in `environments.json`. Requires `GITHUB_TOKEN` in `security-audit/.env`.

Code scanning alerts are bucketed into FE (`/language:javascript-typescript`) and BE (`/language:python`, `/language:actions`) using `most_recent_instance.category`.

**Cache files** (written to `output/github/`, gitignored):
- `data/{repo}-dependabot.json` / `data/{repo}-codescanning.json` — raw payloads
- `security_summary.json` + `cs_categories.json` — aggregated data (used by `--cache`)

## Report format

### CSP Audit table

One row per app/environment/endpoint. `—` means the check could not be evaluated (no CSP header present).

| App | Env | Endpoint | Status | CSP Present | default/script-src | No unsafe-inline | No unsafe-eval | frame-ancestors | CSOD Covered | No Wildcard * |

### MFA Audit table

One row per app/environment (app endpoint only).

| App | Env | Endpoint | Status | MFA Detected |

MFA detection is a passive heuristic — implementations that only surface the second factor after the first credential step will not be detected.

### GitHub Security Alerts table

One row per app. Critical/High counts shown as `C/H`. `NE` = feature not enabled.

| App | Repository | Dependabot Alerts | Code Scanning FE | Code Scanning BE |

## Linting

The project uses SonarQube rules (via IDE). Apply linting suggestions with judgment — not all rules produce better code. Prefer fixes that genuinely improve readability or correctness; skip mechanical compliance that adds noise.
