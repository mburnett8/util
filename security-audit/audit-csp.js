import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

function parseCsp(header) {
  if (!header) return null;
  const directives = {};
  for (const part of header.split(';')) {
    const tokens = part.trim().split(/\s+/);
    if (!tokens[0]) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return directives;
}

function frameAncestorsCoversHost(sources, hostname) {
  return sources.some(src => {
    const host = src.replace(/^https?:\/\//, '');
    if (host.startsWith('*.')) {
      const base = host.slice(2);
      return hostname.endsWith('.' + base) || hostname === base;
    }
    return host === hostname;
  });
}

async function fetchEndpoint(url) {
  try {
    const res = await fetch(url, { method: 'HEAD', redirect: 'follow' });
    return { status: res.status, header: res.headers.get('content-security-policy'), error: null };
  } catch (err) {
    return { status: null, header: null, error: err.message };
  }
}

function evaluateApp(header, csodUrl) {
  const csp = parseCsp(header);
  if (csp == null) {
    return { cspPresent: false, scriptSrcDefined: null, noUnsafeInline: null, noUnsafeEval: null, frameAncestorsDefined: null, csodCovered: null, noWildcard: null };
  }
  const scriptSrc = csp['script-src'] ?? csp['default-src'];
  const frameAncestors = csp['frame-ancestors'];
  const allSources = new Set(Object.values(csp).flat());
  const csodHost = csodUrl ? new URL(csodUrl).hostname : null;
  return {
    cspPresent: true,
    scriptSrcDefined: scriptSrc != null,
    noUnsafeInline: scriptSrc == null ? null : !scriptSrc.includes("'unsafe-inline'"),
    noUnsafeEval: scriptSrc == null ? null : !scriptSrc.includes("'unsafe-eval'"),
    frameAncestorsDefined: frameAncestors != null,
    csodCovered: frameAncestors == null || csodHost == null ? null : frameAncestorsCoversHost(frameAncestors, csodHost),
    noWildcard: !allSources.has('*'),
  };
}

function evaluateS3(header) {
  const csp = parseCsp(header);
  if (csp == null) {
    return { cspPresent: false, scriptSrcDefined: null, noUnsafeInline: null, noUnsafeEval: null, frameAncestorsDefined: null, csodCovered: null, noWildcard: null };
  }
  const allSources = new Set(Object.values(csp).flat());
  return {
    cspPresent: true,
    scriptSrcDefined: null,
    noUnsafeInline: !allSources.has("'unsafe-inline'"),
    noUnsafeEval: !allSources.has("'unsafe-eval'"),
    frameAncestorsDefined: null,
    csodCovered: null,
    noWildcard: !allSources.has('*'),
  };
}

export async function fetchCspData(entries) {
  const results = [];
  for (const entry of entries) {
    for (const [envName, env] of Object.entries(entry.environments)) {
      if (env.app && env.app !== '<placeholder>') {
        const { status, header, error } = await fetchEndpoint(env.app);
        results.push({ name: entry.name, envName, endpoint: 'app', url: env.app, status, header, error, checks: evaluateApp(header, env.csod) });
      }
      if (env.s3 && env.s3 !== '<placeholder>') {
        const { status, header, error } = await fetchEndpoint(env.s3);
        results.push({ name: entry.name, envName, endpoint: 's3', url: env.s3, status, header, error, checks: evaluateS3(header) });
      }
    }
  }
  return results;
}

// --- Standalone CLI ---

function statusEmoji(code) {
  if (code == null) return '🔴';
  return code >= 200 && code < 300 ? '🟢' : '🔴';
}

function printRow(row) {
  const c = row.checks;
  const checkItems = [
    [c.cspPresent, 'CSP header present'],
    ...(c.scriptSrcDefined == null ? [] : [[c.scriptSrcDefined, 'script-src or default-src defined']]),
    ...(c.noUnsafeInline == null ? [] : [
      [c.noUnsafeInline, "No 'unsafe-inline' in script/default-src"],
      [c.noUnsafeEval, "No 'unsafe-eval' in script/default-src"],
    ]),
    ...(c.frameAncestorsDefined == null ? [] : [[c.frameAncestorsDefined, 'frame-ancestors defined']]),
    ...(c.csodCovered == null ? [] : [[c.csodCovered, 'frame-ancestors covers CSOD']]),
    ...(c.noWildcard == null ? [] : [[c.noWildcard, 'No bare wildcard (*) sources']]),
  ];
  const allPass = checkItems.every(([pass]) => pass);
  console.log(`\n  ${allPass ? '✅' : '❌'} ${row.endpoint}: ${row.url}`);
  if (row.error) { console.log(`         ERROR: ${row.error}`); return; }
  console.log(`         Status : ${statusEmoji(row.status)} ${row.status}`);
  console.log(`         CSP    : ${row.header ?? '(none)'}`);
  for (const [pass, label] of checkItems) {
    console.log(`         ${pass ? '✅' : '❌'} ${label}`);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const urls = JSON.parse(readFileSync(join(__dirname, 'urls.json'), 'utf8'));
  let currentGroup = null;
  for (const row of await fetchCspData(urls)) {
    const group = `${row.name} / ${row.envName}`;
    if (group !== currentGroup) {
      console.log(`\n${'─'.repeat(70)}`);
      console.log(group);
      currentGroup = group;
    }
    printRow(row);
  }
  console.log(`\n${'─'.repeat(70)}\n`);
}
