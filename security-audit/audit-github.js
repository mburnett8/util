import dotenv from 'dotenv';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, '.env') });

const ORG = 'Intelladon-LLC';
const TOKEN = process.env.GITHUB_TOKEN;
const API_ORIGIN = 'https://api.github.com';
const HEADERS = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
};

const OUTPUT_DIR = join(__dirname, 'output', 'github');

const CS_CATEGORIES_FE = new Set(['/language:javascript-typescript']);
const CS_CATEGORIES_BE = new Set(['/language:python', '/language:actions']);

function saveJson(name, data) {
  const path = join(OUTPUT_DIR, `${name}.json`);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2));
}

function loadJson(name) {
  return JSON.parse(readFileSync(join(OUTPUT_DIR, `${name}.json`), 'utf8'));
}

function saveMd(name, content) {
  const path = join(OUTPUT_DIR, `${name}.md`);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

async function fetchAlerts(endpoint) {
  const res = await fetch(`${API_ORIGIN}${endpoint}`, { headers: HEADERS });
  return res.json();
}

function apiError(alerts) {
  if (Array.isArray(alerts)) return null;
  return alerts?.message ?? 'unknown error';
}

function processDependabotAlerts(alerts) {
  const err = apiError(alerts);
  if (err === 'no analysis found') return { critical: 0, high: 0, enabled: false, error: null };
  if (err) return { critical: 0, high: 0, enabled: true, error: err };
  let critical = 0, high = 0;
  for (const alert of alerts) {
    if (alert.state !== 'open') continue;
    if (alert.security_advisory.severity === 'critical') critical++;
    if (alert.security_advisory.severity === 'high') high++;
  }
  return { critical, high, enabled: true, error: null };
}

function countBySeverity(alerts, categorySet) {
  let critical = 0, high = 0;
  for (const alert of alerts) {
    if (alert.state !== 'open') continue;
    if (!categorySet.has(alert.most_recent_instance.category)) continue;
    if (alert.rule.security_severity_level === 'critical') critical++;
    if (alert.rule.security_severity_level === 'high') high++;
  }
  return { critical, high };
}

function buildCategories(alerts) {
  const categories = {};
  for (const alert of alerts) {
    if (alert.state !== 'open') continue;
    const cat = alert.most_recent_instance.category;
    categories[cat] = (categories[cat] ?? 0) + 1;
  }
  return categories;
}

function processCodeScanningAlerts(alerts) {
  const err = apiError(alerts);
  if (err === 'no analysis found') return { critical_fe: 0, high_fe: 0, critical_be: 0, high_be: 0, enabled: false, error: null, categories: {} };
  if (err) return { critical_fe: 0, high_fe: 0, critical_be: 0, high_be: 0, enabled: true, error: err, categories: {} };

  const fe = countBySeverity(alerts, CS_CATEGORIES_FE);
  const be = countBySeverity(alerts, CS_CATEGORIES_BE);
  return { critical_fe: fe.critical, high_fe: fe.high, critical_be: be.critical, high_be: be.high, enabled: true, error: null, categories: buildCategories(alerts) };
}

export async function fetchGithubData(entries, useCache = false) {
  if (useCache) {
    return {
      summary: loadJson('security_summary'),
      csCategories: loadJson('cs_categories'),
    };
  }

  const summary = {};
  const csCategories = {};

  for (const entry of entries.filter(e => e.repo)) {
    process.stdout.write(`  ${entry.name} (${entry.repo})... `);

    const dbAlerts = await fetchAlerts(`/repos/${ORG}/${entry.repo}/dependabot/alerts?severity=critical,high`);
    saveJson(`data/${entry.repo}-dependabot`, dbAlerts);

    const csAlerts = await fetchAlerts(`/repos/${ORG}/${entry.repo}/code-scanning/alerts?severity=critical,high`);
    saveJson(`data/${entry.repo}-codescanning`, csAlerts);

    const db = processDependabotAlerts(dbAlerts);
    const cs = processCodeScanningAlerts(csAlerts);

    for (const [cat, count] of Object.entries(cs.categories)) {
      csCategories[cat] = (csCategories[cat] ?? 0) + count;
    }

    summary[entry.repo] = {
      dependabot_alerts: { critical: db.critical, high: db.high, enabled: db.enabled },
      codescanning_alerts: {
        critical_fe: cs.critical_fe, high_fe: cs.high_fe,
        critical_be: cs.critical_be, high_be: cs.high_be,
        enabled: cs.enabled,
      },
    };

    console.log('done');
  }

  saveJson('security_summary', summary);
  saveJson('cs_categories', csCategories);

  return { summary, csCategories };
}

// --- Standalone CLI ---

function alertCell(error, enabled, ...counts) {
  if (error) return 'ERR';
  if (!enabled) return 'NE';
  return counts.join('/');
}

function center(str, width) {
  const pad = width - str.length;
  if (pad <= 0) return str;
  const left = Math.floor(pad / 2);
  return ' '.repeat(left) + str + ' '.repeat(pad - left);
}

function buildMarkdownTable(entries, summary) {
  const today = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  const headers = ['App', 'Dependabot Alerts', 'Code Scanning FE', 'Code Scanning BE'];

  const rows = entries
    .filter(e => e.repo)
    .map(e => {
      const data = summary[e.repo];
      if (!data) return [e.name, '—', '—', '—'];
      const db = data.dependabot_alerts;
      const cs = data.codescanning_alerts;
      return [
        e.name,
        alertCell(db.error, db.enabled, db.critical, db.high),
        alertCell(cs.error, cs.enabled, cs.critical_fe, cs.high_fe),
        alertCell(cs.error, cs.enabled, cs.critical_be, cs.high_be),
      ];
    });

  const colWidths = headers.map(h => h.length);
  for (const row of rows) {
    row.forEach((cell, i) => { colWidths[i] = Math.max(colWidths[i], cell.length); });
  }

  const headerRow = '| ' + headers.map((h, i) => h.padEnd(colWidths[i])).join(' | ') + ' |';
  const sepRow = '| ' + colWidths.map((w, i) =>
    i === 0 ? ':' + '-'.repeat(w - 1) : ':' + '-'.repeat(w - 2) + ':'
  ).join(' | ') + ' |';
  const dataRows = rows.map(row =>
    '| ' + row.map((cell, i) => i === 0 ? cell.padEnd(colWidths[i]) : center(cell, colWidths[i])).join(' | ') + ' |'
  );

  return [
    '# Security Alerts Summary',
    '',
    `*Generated on ${today}*`,
    '',
    "Results are shown as Critical/High counts. 'NE' indicates that the feature is Not Enabled for the repository.",
    '',
    headerRow,
    sepRow,
    ...dataRows,
  ].join('\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const useCache = process.argv.includes('--cache');
  const urls = JSON.parse(readFileSync(join(__dirname, 'urls.json'), 'utf8'));

  if (!TOKEN && !useCache) {
    console.error('Error: GITHUB_TOKEN is not set. Add it to .env in the project root.');
    process.exit(1);
  }

  const repoCount = urls.filter(e => e.repo).length;
  console.log(useCache ? 'Loading from cache...' : `Fetching alerts for ${repoCount} repos...`);
  const { summary } = await fetchGithubData(urls, useCache);
  const md = buildMarkdownTable(urls, summary);
  saveMd('security_summary', md);

  console.log(`\nDone. ${Object.keys(summary).length} repos processed.`);
  console.log('Report: security-audit/output/github/security_summary.md');
}
