import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const MFA_PATTERNS = [
  { re: /name=["'][^"']*otp[^"']*["']/i,   indicator: 'OTP input field' },
  { re: /id=["'][^"']*otp[^"']*["']/i,     indicator: 'OTP input field' },
  { re: /two[\s-]factor/i,                  indicator: 'Two-factor text' },
  { re: /authenticator app/i,               indicator: 'Authenticator app text' },
  { re: /verification code/i,               indicator: 'Verification code text' },
  { re: /one[\s-]time password/i,           indicator: 'One-time password text' },
  { re: /\btotp\b/i,                        indicator: 'TOTP reference' },
];

function checkMfa(body) {
  if (!body) return { detected: false, indicator: null };
  const match = MFA_PATTERNS.find(({ re }) => re.test(body));
  return match ? { detected: true, indicator: match.indicator } : { detected: false, indicator: null };
}

async function fetchApp(url) {
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow' });
    return { status: res.status, body: await res.text(), error: null };
  } catch (err) {
    return { status: null, body: null, error: err.message };
  }
}

export async function fetchMfaData(entries) {
  const results = [];
  for (const entry of entries) {
    for (const [envName, env] of Object.entries(entry.environments)) {
      if (!env.app || env.app === '<placeholder>') continue;
      const { status, body, error } = await fetchApp(env.app);
      const mfa = checkMfa(body);
      results.push({ name: entry.name, envName, url: env.app, status, error, mfaDetected: mfa.detected, indicator: mfa.indicator });
    }
  }
  return results;
}

// --- Standalone CLI ---

function statusEmoji(code) {
  if (code == null) return '🔴';
  return code >= 200 && code < 300 ? '🟢' : '🔴';
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const environments = JSON.parse(readFileSync(join(__dirname, 'environments.json'), 'utf8'));
  for (const row of await fetchMfaData(environments)) {
    console.log(`\n${'─'.repeat(70)}`);
    console.log(`${row.name} / ${row.envName}`);
    if (row.error) {
      console.log(`\n  ❌ ${row.url}`);
      console.log(`         ERROR: ${row.error}`);
      continue;
    }
    const mfaDetail = row.mfaDetected ? `Detected (${row.indicator})` : 'Not detected';
    console.log(`\n  ${row.mfaDetected ? '✅' : '❌'} ${row.url}`);
    console.log(`         Status : ${statusEmoji(row.status)} ${row.status}`);
    console.log(`         MFA    : ${mfaDetail}`);
  }
  console.log(`\n${'─'.repeat(70)}\n`);
}
