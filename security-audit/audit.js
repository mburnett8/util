import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { fetchCspData } from './audit-csp.js';
import { fetchMfaData } from './audit-mfa.js';
import { fetchGithubData } from './audit-github.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const environments = JSON.parse(readFileSync(join(__dirname, 'environments.json'), 'utf8'));

// --- HTML builders ---

const icon = {
  pass: '<iconify-icon icon="ph:check-circle-fill" class="icon pass"></iconify-icon>',
  fail: '<iconify-icon icon="ph:x-circle-fill"    class="icon fail"></iconify-icon>',
  na:   '<iconify-icon icon="ph:minus"             class="icon na"></iconify-icon>',
  err:  '<iconify-icon icon="ph:warning-fill"      class="icon err"></iconify-icon>',
};

function cell(content) {
  return `<td>${content}</td>`;
}

function fmtHtml(val) {
  if (val === null || val === undefined) return icon.na;
  return val ? icon.pass : icon.fail;
}

function statusHtml(code, error) {
  if (error) return `${icon.err} <span class="err">ERROR</span>`;
  if (code == null) return icon.na;
  const cls = code >= 200 && code < 300 ? 'pass' : 'fail';
  return `<span class="status-badge ${cls}">${code}</span>`;
}

function alertCellHtml(error, enabled, ...counts) {
  if (error) return `${icon.err} <span class="err">ERR</span>`;
  if (!enabled) return `<span class="na">NE</span>`;
  const total = counts.reduce((a, b) => a + b, 0);
  const cls = total > 0 ? 'fail' : 'pass';
  return `<span class="alert-count ${cls}">${counts.join('/')}</span>`;
}

function buildCspHtml(results) {
  const headers = ['App', 'Env', 'Endpoint', 'Status', 'CSP Present', 'default/script-src', 'No unsafe-inline', 'No unsafe-eval', 'frame-ancestors', 'CSOD Covered', 'No Wildcard *'];
  const rows = results.map(row => {
    const c = row.checks;
    const endpoint = `<a href="${row.url}" target="_blank">${row.endpoint}</a>`;
    return `<tr data-env="${row.envName}">
      ${cell(row.name)}${cell(row.envName)}${cell(endpoint)}${cell(statusHtml(row.status, row.error))}
      ${cell(fmtHtml(c.cspPresent))}${cell(fmtHtml(c.scriptSrcDefined))}
      ${cell(fmtHtml(c.noUnsafeInline))}${cell(fmtHtml(c.noUnsafeEval))}
      ${cell(fmtHtml(c.frameAncestorsDefined))}${cell(fmtHtml(c.csodCovered))}
      ${cell(fmtHtml(c.noWildcard))}
    </tr>`;
  }).join('\n');

  return `<section>
  <h2>CSP Audit</h2>
  <table>
    <thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p class="note">${icon.na} indicates the check could not be evaluated because no CSP header was present.</p>
</section>`;
}

function buildMfaHtml(results) {
  const headers = ['App', 'Env', 'Endpoint', 'Status', 'MFA Detected'];
  const rows = results.map(row => {
    const endpoint = `<a href="${row.url}" target="_blank">app</a>`;
    return `<tr data-env="${row.envName}">
      ${cell(row.name)}${cell(row.envName)}${cell(endpoint)}
      ${cell(statusHtml(row.status, row.error))}${cell(fmtHtml(row.mfaDetected))}
    </tr>`;
  }).join('\n');

  return `<section>
  <h2>MFA Audit</h2>
  <table>
    <thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p class="note">MFA detection is a passive heuristic — the login page HTML is scanned for OTP input fields, two-factor text, and authenticator references. Implementations that only surface the second factor after the first credential step will not be detected here.</p>
</section>`;
}

function buildGithubHtml(entries, summary) {
  const headers = ['App', 'Repository', 'Dependabot Alerts', 'Code Scanning FE', 'Code Scanning BE'];
  const rows = entries.filter(e => e.repo).map(e => {
    const data = summary[e.repo];
    if (!data) return `<tr>${cell(e.name)}${cell(e.repo)}${cell(icon.na)}${cell(icon.na)}${cell(icon.na)}</tr>`;
    const db = data.dependabot_alerts;
    const cs = data.codescanning_alerts;
    return `<tr>
      ${cell(e.name)}${cell(e.repo)}
      ${cell(alertCellHtml(db.error, db.enabled, db.critical, db.high))}
      ${cell(alertCellHtml(cs.error, cs.enabled, cs.critical_fe, cs.high_fe))}
      ${cell(alertCellHtml(cs.error, cs.enabled, cs.critical_be, cs.high_be))}
    </tr>`;
  }).join('\n');

  return `<section>
  <h2>GitHub Security Alerts</h2>
  <table>
    <thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p class="note">Results are shown as Critical/High counts. NE = feature not enabled.</p>
</section>`;
}

function buildHtml(today, cspData, mfaData, entries, summary) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit — ${today}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/iconify-icon@2/dist/iconify-icon.min.js"></script>
  <style>
    body { font-family: 'Inter', sans-serif; max-width: 1200px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { font-size: 1.6rem; font-weight: 600; margin-bottom: 0.2rem; }
    .generated { color: #777; font-size: 0.875rem; margin-top: 0; margin-bottom: 2.5rem; }
    section { margin-bottom: 3rem; }
    h2 { font-size: 1.1rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: #444; border-bottom: 2px solid #e5e5e5; padding-bottom: 0.4rem; margin-bottom: 1rem; }
    table { border-collapse: collapse; font-size: 0.78rem; }
    th { background: #f6f6f6; font-weight: 500; text-align: left; padding: 0.5rem 0.75rem; border: 1px solid #e0e0e0; white-space: nowrap; color: #444; }
    td { padding: 0.45rem 0.75rem; border: 1px solid #e0e0e0; }
    td:first-child { white-space: nowrap; }
    tr:nth-child(even) td { background: #fafafa; }
    td:not(:first-child) { text-align: center; }
    th:not(:first-child) { text-align: center; }
    iconify-icon.icon { font-size: 1.1rem; vertical-align: middle; }
    iconify-icon.pass { color: #16a34a; }
    iconify-icon.fail { color: #dc2626; }
    iconify-icon.na   { color: #bbb; }
    iconify-icon.err  { color: #d97706; }
    .status-badge { display: inline-block; font-size: 0.75rem; font-weight: 500; padding: 2px 8px; border-radius: 4px; }
    .status-badge.pass { background: #dcfce7; color: #15803d; }
    .status-badge.fail { background: #fee2e2; color: #b91c1c; }
    .alert-count { font-weight: 600; }
    .alert-count.pass { color: #16a34a; }
    .alert-count.fail { color: #dc2626; }
    .na   { color: #bbb; }
    .err  { color: #d97706; font-weight: 600; }
    .note { font-size: 0.78rem; color: #888; margin-top: 0.5rem; }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .env-toggle { display: inline-flex; background: #ebebeb; border-radius: 8px; padding: 3px; gap: 2px; margin-bottom: 2rem; }
    .env-btn { border: none; background: transparent; padding: 5px 20px; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.825rem; font-weight: 500; color: #666; transition: all 0.15s; }
    .env-btn.active { background: #fff; color: #1a1a1a; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
  </style>
</head>
<body>
  <h1>Security Audit</h1>
  <p class="generated">Generated: ${today}</p>
  <div class="env-toggle">
    <button class="env-btn" data-filter="dev">Dev</button>
    <button class="env-btn active" data-filter="prod">Prod</button>
  </div>
  ${buildCspHtml(cspData)}
  ${buildMfaHtml(mfaData)}
  ${buildGithubHtml(entries, summary)}
  <script>
    const btns = document.querySelectorAll('.env-btn');
    const rows = document.querySelectorAll('tr[data-env]');
    function setFilter(env) {
      btns.forEach(b => b.classList.toggle('active', b.dataset.filter === env));
      rows.forEach(r => { r.style.display = r.dataset.env === env ? '' : 'none'; });
    }
    btns.forEach(b => b.addEventListener('click', () => setFilter(b.dataset.filter)));
    setFilter('prod');
  </script>
</body>
</html>`;
}

// --- Main ---

const today = new Date().toISOString().split('T')[0];

console.log('Running CSP audit...');
const cspData = await fetchCspData(environments);

console.log('Running MFA audit...');
const mfaData = await fetchMfaData(environments);

console.log('Running GitHub security audit...');
const { summary } = await fetchGithubData(environments);

const outDir = join(__dirname, 'results');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, `security-audit-${today}.html`), buildHtml(today, cspData, mfaData, environments, summary));

console.log(`\nReport: results/security-audit-${today}.html`);
