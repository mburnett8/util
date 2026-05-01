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


function saveJson(name, data) {
  const path = join(OUTPUT_DIR, `${name}.json`);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2));
}

function loadJson(name) {
  return JSON.parse(readFileSync(join(OUTPUT_DIR, `${name}.json`), 'utf8'));
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

const CS_CATEGORIES_FE = new Set(['/language:javascript-typescript']);
const CS_CATEGORIES_BE = new Set(['/language:python', '/language:actions']);

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

function processCodeScanningAlerts(alerts) {
  const err = apiError(alerts);
  if (err === 'no analysis found') return { critical_fe: 0, high_fe: 0, critical_be: 0, high_be: 0, enabled: false, error: null };
  if (err) return { critical_fe: 0, high_fe: 0, critical_be: 0, high_be: 0, enabled: true, error: err };
  const fe = countBySeverity(alerts, CS_CATEGORIES_FE);
  const be = countBySeverity(alerts, CS_CATEGORIES_BE);
  return { critical_fe: fe.critical, high_fe: fe.high, critical_be: be.critical, high_be: be.high, enabled: true, error: null };
}

export async function fetchGithubData(entries, useCache = false) {
  if (useCache) {
    return { summary: loadJson('security_summary') };
  }

  const summary = {};

  for (const entry of entries.filter(e => e.repo)) {
    process.stdout.write(`  ${entry.name} (${entry.repo})... `);

    const dbAlerts = await fetchAlerts(`/repos/${ORG}/${entry.repo}/dependabot/alerts?severity=critical,high`);
    saveJson(`data/${entry.repo}-dependabot`, dbAlerts);

    const csAlerts = await fetchAlerts(`/repos/${ORG}/${entry.repo}/code-scanning/alerts?severity=critical,high`);
    saveJson(`data/${entry.repo}-codescanning`, csAlerts);

    const db = processDependabotAlerts(dbAlerts);
    const cs = processCodeScanningAlerts(csAlerts);

    summary[entry.repo] = {
      dependabot_alerts: { critical: db.critical, high: db.high, enabled: db.enabled, error: db.error },
      codescanning_alerts: {
        critical_fe: cs.critical_fe, high_fe: cs.high_fe,
        critical_be: cs.critical_be, high_be: cs.high_be,
        enabled: cs.enabled, error: cs.error,
      },
    };

    console.log('done');
  }

  saveJson('security_summary', summary);

  return { summary };
}

// --- Standalone CLI ---

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const useCache = process.argv.includes('--cache');
  const environments = JSON.parse(readFileSync(join(__dirname, 'environments.json'), 'utf8'));

  if (!TOKEN && !useCache) {
    console.error('Error: GITHUB_TOKEN is not set. Add it to .env in the project root.');
    process.exit(1);
  }

  const repoCount = environments.filter(e => e.repo).length;
  console.log(useCache ? 'Loading from cache...' : `Fetching alerts for ${repoCount} repos...`);
  const { summary } = await fetchGithubData(environments, useCache);

  console.log(`\nDone. ${Object.keys(summary).length} repos processed.`);
  console.log('Cache: security-audit/output/github/security_summary.json');
}
