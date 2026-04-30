import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { fetchCspData } from './audit-csp.js';
import { fetchMfaData } from './audit-mfa.js';
import { fetchGithubData } from './audit-github.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const urls = JSON.parse(readFileSync(join(__dirname, 'urls.json'), 'utf8'));

// --- Helpers ---

function alertCell(error, enabled, ...counts) {
  if (error) return 'ERR';
  if (!enabled) return 'NE';
  return counts.join('/');
}

function fmt(val) {
  if (val === null || val === undefined) return '—';
  return val ? '✅' : '❌';
}

function statusCell(code, error) {
  if (error) return '🔴 ERROR';
  if (code == null) return '🔴 —';
  return `${code >= 200 && code < 300 ? '🟢' : '🔴'} ${code}`;
}

// --- Section builders ---

function buildCspSection(results) {
  const header = '| App | Env | Endpoint | Status | CSP Present | default/script-src | No unsafe-inline | No unsafe-eval | frame-ancestors | CSOD Covered | No Wildcard * |';
  const sep    = '|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|';

  const rows = results.map(row => {
    const c = row.checks;
    const endpoint = `[${row.endpoint}](${row.url})`;
    return `| ${row.name} | ${row.envName} | ${endpoint} | ${statusCell(row.status, row.error)} | ${fmt(c.cspPresent)} | ${fmt(c.scriptSrcDefined)} | ${fmt(c.noUnsafeInline)} | ${fmt(c.noUnsafeEval)} | ${fmt(c.frameAncestorsDefined)} | ${fmt(c.csodCovered)} | ${fmt(c.noWildcard)} |`;
  });

  return [
    '## CSP Audit',
    '',
    header,
    sep,
    ...rows,
    '',
    '> `—` indicates the check could not be evaluated because no CSP header was present.',
  ].join('\n');
}

function buildMfaSection(results) {
  const header = '| App | Env | Endpoint | Status | MFA Detected |';
  const sep    = '|---|---|---|:---:|:---:|';

  const rows = results.map(row =>
    `| ${row.name} | ${row.envName} | [app](${row.url}) | ${statusCell(row.status, row.error)} | ${fmt(row.mfaDetected)} |`
  );

  return [
    '## MFA Audit',
    '',
    header,
    sep,
    ...rows,
    '',
    '> MFA detection is a passive heuristic — the login page HTML is scanned for OTP input fields, two-factor text, and authenticator references. Implementations that only surface the second factor after the first credential step will not be detected here.',
  ].join('\n');
}

function buildGithubSection(entries, summary) {
  const header = '| App | Repository | Dependabot Alerts | Code Scanning FE | Code Scanning BE |';
  const sep    = '|---|---|:---:|:---:|:---:|';

  const rows = entries
    .filter(e => e.repo)
    .map(e => {
      const data = summary[e.repo];
      if (!data) return `| ${e.name} | ${e.repo} | — | — | — |`;
      const db = data.dependabot_alerts;
      const cs = data.codescanning_alerts;
      const dbCell = alertCell(db.error, db.enabled, db.critical, db.high);
      const feCell = alertCell(cs.error, cs.enabled, cs.critical_fe, cs.high_fe);
      const beCell = alertCell(cs.error, cs.enabled, cs.critical_be, cs.high_be);
      return `| ${e.name} | ${e.repo} | ${dbCell} | ${feCell} | ${beCell} |`;
    });

  return [
    '## GitHub Security Alerts',
    '',
    header,
    sep,
    ...rows,
    '',
    "> Results are shown as Critical/High counts. 'NE' indicates that the feature is Not Enabled for the repository.",
  ].join('\n');
}

// --- Main ---

const today = new Date().toISOString().split('T')[0];

console.log('Running CSP audit...');
const cspData = await fetchCspData(urls);

console.log('Running MFA audit...');
const mfaData = await fetchMfaData(urls);

console.log('Running GitHub security audit...');
const { summary } = await fetchGithubData(urls);

const report = [
  '# Security Audit',
  '',
  `Generated: ${today}`,
  '',
  buildCspSection(cspData),
  '',
  '---',
  '',
  buildMfaSection(mfaData),
  '',
  '---',
  '',
  buildGithubSection(urls, summary),
].join('\n');

const outPath = join(__dirname, 'results', `security-audit-${today}.md`);
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, report);

console.log(`\nReport: results/security-audit-${today}.md`);
