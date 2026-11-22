// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

/* Netra node-isolation workflow against a demo server wired to tests/fake_netra.py:
   FAKE_NETRA_PORT=18870 python3 tests/fake_netra.py &
   DUVORA_NETRA_URL=http://127.0.0.1:18870 DUVORA_NETRA_API_KEY=netra-test-key-0123456789abcdef \
   DUVORA_NETRA_DISCOVER=1 DUVORA_NETRA_ENFORCE=1 DUVORA_NETRA_INTERVAL=5 python -m duvora.server --demo --db /tmp/e2e-netra.db &
   node tests/e2e_netra.cjs */
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const fs = require('node:fs');

const URL = process.env.DUVORA_URL || 'http://127.0.0.1:8787';
const DEVICE = 'netra-dpu-node-1';

async function shot(page, name) {
  await page.mouse.move(1400, 1150);
  await page.waitForTimeout(800);
  await page.screenshot({ path: `test-results/${name}.png`, fullPage: true });
}

async function menu(page, group, item) {
  await page.getByRole('button', { name: group, exact: true }).click();
  await page.getByRole('region', { name: group }).getByRole('button', { name: new RegExp('^' + item) }).click();
}

(async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('dialog', (d) => d.accept());
  fs.mkdirSync('test-results', { recursive: true });

  await page.goto(URL);
  await page.getByLabel('Username').fill(process.env.DUVORA_USER || 'admin');
  await page.getByLabel('Password').fill(process.env.DUVORA_PASSWORD || 'Admin@321');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByText('FLEET PULSE').waitFor();

  await menu(page, 'Fleet', 'Telemetry');
  await page.getByRole('table', { name: 'Kernel observations' }).getByText(DEVICE).waitFor();
  await shot(page, 'netra-telemetry');

  await menu(page, 'Operate', 'Isolation');
  const table = page.getByRole('table', { name: 'Node isolation' });
  const row = table.getByRole('row').filter({ hasText: DEVICE });
  await row.getByRole('button', { name: 'Shadow allow-list' }).click();
  await page.getByLabel('Allowed destination CIDR').fill('10.0.0.0/8');
  await page.getByLabel('Allowed ports (comma separated; empty = all)').fill('443');
  await page.getByRole('button', { name: 'Preview change' }).click();
  await page.getByRole('table', { name: 'Shadow replay' }).waitFor();
  await page.getByRole('button', { name: 'Apply shadow' }).click();
  await row.getByRole('button', { name: 'Promote to enforce' }).waitFor({ timeout: 20000 });
  await shot(page, 'netra-shadow');

  await row.getByRole('button', { name: 'Promote to enforce' }).click();
  await page.getByRole('button', { name: 'Preview change' }).click();
  const enforce = page.getByRole('button', { name: 'Enforce in kernel' });
  assert.equal(await enforce.isDisabled(), true);
  await page.getByLabel(`Type ENFORCE ON ${DEVICE} to confirm`).fill(`ENFORCE ON ${DEVICE}`);
  await enforce.click();
  await row.getByRole('button', { name: 'Back to shadow' }).waitFor({ timeout: 20000 });
  await row.getByText('enforce', { exact: true }).waitFor({ timeout: 20000 });
  await shot(page, 'netra-enforce');

  await page.getByRole('button', { name: 'Kill switch', exact: true }).click();
  await page.getByText(/Kill switch engaged/).first().waitFor();
  await row.getByRole('button', { name: 'Promote to enforce' }).waitFor({ timeout: 20000 });
  await shot(page, 'netra-kill-switch');
  await page.getByRole('button', { name: 'Release kill switch' }).click();

  await row.getByRole('button', { name: 'Release' }).click();
  await page.getByRole('button', { name: 'Preview change' }).click();
  await page.getByRole('button', { name: 'Release isolation' }).click();
  await row.getByRole('button', { name: 'Shadow allow-list' }).waitFor({ timeout: 20000 });

  await menu(page, 'Govern', 'Capabilities');
  await page.getByRole('table', { name: 'eBPF capability probe' }).waitFor();
  await shot(page, 'netra-capabilities');

  assert.deepEqual(errors, []);
  await browser.close();
  console.log('Netra console workflow passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
