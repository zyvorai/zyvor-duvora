// Capture the README console gallery (docs/ux/console-*.jpg) from a throwaway demo server.
// Needs a built console (make web), Google Chrome, macOS `sips`, and Playwright:
//   npm install --no-save playwright@1.63.0 && node docs/ux/build-console-shots.cjs
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');

const ROOT = path.resolve(__dirname, '../..');
const PORT = process.env.SHOTS_PORT || '8799';
const URL = `http://127.0.0.1:${PORT}`;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'duvora-shots-'));
const PAGES = [
  ['overview', null, null],
  ['steering', 'Operate', 'Steering'],
  ['ai-traffic', 'AI security', 'AI traffic'],
  ['threats', 'AI security', 'Threats'],
  ['report', 'Monitor', 'Report'],
  ['services', 'Operate', 'Services'],
];

async function waitHealthy() {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(`${URL}/healthz`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('demo server did not start');
}

async function seed(request) {
  const api = async (method, p, data) => {
    const res = await request.fetch(`${URL}/api/v1${p}`, { method, data: data || {} });
    if (!res.ok()) throw new Error(`${method} ${p}: ${res.status()} ${await res.text()}`);
    return res.json();
  };
  const plan = await api('POST', '/plans', { action: 'steer', devices: ['bf3-01', 'bf3-02', 'bf3-03'], ruleset: 'ai-gateway', stage: 'shadow' });
  await api('POST', `/plans/${plan.id}/apply`, { confirmation: plan.confirmation });
  await api('PUT', '/intel/feeds/tor-exits', { description: 'Tor exit ranges (sample)', format: 'plain', indicators: '185.220.101.0/24\n185.220.102.0/24\n' });
}

(async () => {
  const server = spawn('python3', ['-m', 'duvora.server', '--demo', '--port', PORT, '--db', path.join(TMP, 'shots.db')],
    { cwd: ROOT, stdio: 'ignore', env: { ...process.env, DUVORA_ADMIN_PASSWORD: 'Gallery@4821' } });
  try {
    await waitHealthy();
    const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1120 }, deviceScaleFactor: 2 });
    const page = await context.newPage();
    await page.goto(URL);
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill('Gallery@4821');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByText('FLEET PULSE').waitFor();
    await seed(context.request);
    // A few simulator ticks so verdicts, findings and intel matches exist.
    await page.waitForTimeout(Number(process.env.SHOTS_SETTLE_MS || 25000));
    for (const [name, group, item] of PAGES) {
      if (group) {
        await page.getByRole('button', { name: group, exact: true }).click();
        await page.getByRole('region', { name: group }).getByRole('button', { name: new RegExp('^' + item) }).click();
      } else {
        await page.reload();
        await page.getByText('FLEET PULSE').waitFor();
      }
      await page.mouse.move(1400, 1100);
      await page.waitForTimeout(1500);
      const png = path.join(TMP, `${name}.png`);
      await page.screenshot({ path: png });
      const out = path.join(__dirname, `console-${name}.jpg`);
      execFileSync('sips', ['-s', 'format', 'jpeg', '-s', 'formatOptions', '82', png, '--out', out], { stdio: 'ignore' });
      console.log(`wrote docs/ux/console-${name}.jpg`);
    }
    await browser.close();
  } finally {
    server.kill();
    fs.rmSync(TMP, { recursive: true, force: true });
  }
})().catch((e) => { console.error(e); process.exit(1); });
