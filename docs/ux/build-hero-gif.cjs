// Capture a console walk-through on a throwaway demo server and convert it to docs/ux/anim/hero.gif.
// Needs a built console (make web), Google Chrome, ffmpeg, and Playwright:
//   npm install --no-save playwright@1.63.0 && node docs/ux/build-hero-gif.cjs
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');

const ROOT = path.resolve(__dirname, '../..');
const PORT = process.env.SHOTS_PORT || '8798';
const URL = `http://127.0.0.1:${PORT}`;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'duvora-hero-'));
const STEPS = [['Operate', 'Steering'], ['AI security', 'AI traffic'], ['AI security', 'Threats'], ['Monitor', 'Report']];

async function waitHealthy() {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(`${URL}/healthz`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('demo server did not start');
}

(async () => {
  const server = spawn('python3', ['-m', 'duvora.server', '--demo', '--port', PORT, '--db', path.join(TMP, 'hero.db')],
    { cwd: ROOT, stdio: 'ignore', env: { ...process.env, DUVORA_ADMIN_PASSWORD: 'Gallery@4821' } });
  try {
    await waitHealthy();
    const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
    const warm = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const w = await warm.newPage();
    await w.goto(URL);
    await w.getByLabel('Username').fill('admin');
    await w.getByLabel('Password').fill('Gallery@4821');
    await w.getByRole('button', { name: 'Sign in' }).click();
    await w.getByText('FLEET PULSE').waitFor();
    await w.waitForTimeout(Number(process.env.SHOTS_SETTLE_MS || 20000));
    const state = await warm.storageState();
    await warm.close();

    // Playwright video needs its own ffmpeg download, so capture frames and let system ffmpeg build the loop.
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, storageState: state });
    const page = await ctx.newPage();
    await page.goto(URL);
    await page.getByText('FLEET PULSE').waitFor();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(TMP, 'f0.png') });
    let n = 1;
    for (const [group, item] of STEPS) {
      await page.getByRole('button', { name: group, exact: true }).click();
      await page.getByRole('region', { name: group }).getByRole('button', { name: new RegExp('^' + item) }).click();
      await page.mouse.move(1270, 790);
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(TMP, `f${n++}.png`) });
    }
    await ctx.close();
    await browser.close();
    const out = path.join(__dirname, 'anim', 'hero.gif');
    const hold = 2.4;
    execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-framerate', String(1 / hold), '-i', path.join(TMP, 'f%d.png'), '-vf',
      'scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=3', '-loop', '0', out]);
    console.log(`wrote ${path.relative(ROOT, out)} (${(fs.statSync(out).size / 1e6).toFixed(1)} MB)`);
  } finally {
    server.kill();
    fs.rmSync(TMP, { recursive: true, force: true });
  }
})().catch((e) => { console.error(e); process.exit(1); });
