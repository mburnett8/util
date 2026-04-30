# Security Audit

Generated: 2026-04-30

## CSP Audit

| App | Env | Endpoint | Status | CSP Present | default/script-src | No unsafe-inline | No unsafe-eval | frame-ancestors | CSOD Covered | No Wildcard * |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| koh-ksr | dev | [app](https://koh-ksr-dev-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| koh-ksr | dev | [s3](https://koh-ksr-dev-0-fst-vib14r0b.s3.amazonaws.com/static/index.html) | 🟢 200 | ❌ | — | — | — | — | — | — |
| koh-ksr | prod | [app](https://koh-ksr-prod-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| koh-ksr | prod | [s3](https://koh-ksr-prod-0-fst-w3jel5cj.s3.us-east-1.amazonaws.com/static/index.html) | 🟢 200 | ❌ | — | — | — | — | — | — |
| cjp-crt | dev | [app](https://cjp-crt-dev-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ❌ | — | — | — | — | — | — |
| cjp-crt | dev | [s3](https://cjp-crt-dev-0-app-dxchcm.s3.us-east-1.amazonaws.com/static/index.html) | 🟢 200 | ❌ | — | — | — | — | — | — |
| cjp-crt | prod | [app](https://cjp-crt-prod-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ❌ | — | — | — | — | — | — |
| cjp-crt | prod | [s3](https://cjp-crt-prod-0-app-tsfrda79.s3.us-east-1.amazonaws.com/static/index.html) | 🟢 200 | ❌ | — | — | — | — | — | — |
| fme-app | dev | [app](https://fme-app-dev-0-web.tribridge-amplifyhr.eu/admin/login/) | 🟢 200 | ❌ | — | — | — | — | — | — |
| fme-app | dev | [s3](https://fme-app-dev-app-ivdswogf.s3.eu-west-1.amazonaws.com/index.html) | 🟢 200 | ❌ | — | — | — | — | — | — |
| fme-app | prod | [app](https://fme-app-prod-0-web.tribridge-amplifyhr.eu/admin/login/) | 🟢 200 | ❌ | — | — | — | — | — | — |
| fme-app | prod | [s3](https://fme-app-prod-app-i033f1oc.s3.eu-west-1.amazonaws.com/index.html) | 🟢 200 | ❌ | — | — | — | — | — | — |

> `—` indicates the check could not be evaluated because no CSP header was present.

---

## MFA Audit

| App | Env | Endpoint | Status | MFA Detected |
|---|---|---|:---:|:---:|
| koh-ksr | dev | [app](https://koh-ksr-dev-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ✅ |
| koh-ksr | prod | [app](https://koh-ksr-prod-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ✅ |
| cjp-crt | dev | [app](https://cjp-crt-dev-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ✅ |
| cjp-crt | prod | [app](https://cjp-crt-prod-0-web.tribridge-amplifyhr.com/admin/login/) | 🟢 200 | ✅ |
| fme-app | dev | [app](https://fme-app-dev-0-web.tribridge-amplifyhr.eu/admin/login/) | 🟢 200 | ✅ |
| fme-app | prod | [app](https://fme-app-prod-0-web.tribridge-amplifyhr.eu/admin/login/) | 🟢 200 | ✅ |

> MFA detection is a passive heuristic — the login page HTML is scanned for OTP input fields, two-factor text, and authenticator references. Implementations that only surface the second factor after the first credential step will not be detected here.

---

## GitHub Security Alerts

| App | Repository | Dependabot Alerts | Code Scanning FE | Code Scanning BE |
|---|---|:---:|:---:|:---:|
| koh-ksr | koh_ksr_app | 0/30 | 0/0 | 0/0 |
| cjp-crt | cjpia_certificates | 0/11 | 0/0 | 0/0 |
| fme-app | fresenius | 0/23 | 0/1 | 0/2 |

> Results are shown as Critical/High counts. 'NE' indicates that the feature is Not Enabled for the repository.