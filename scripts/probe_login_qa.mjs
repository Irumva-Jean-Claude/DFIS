import { chromium } from 'playwright';
import run from '../login_qa.mjs';

const url = process.env.QA_URL || 'http://localhost:8000';
const launchOpts = {};
if (process.env.PW_EXECUTABLE) launchOpts.executablePath = process.env.PW_EXECUTABLE;
const browser = await chromium.launch(launchOpts);
const page = await browser.newPage();
page.on('console', m => console.log('[console]', m.type(), m.text()));
page.on('pageerror', e => console.log('[pageerror]', e.message));
page.on('requestfailed', r => console.log('[reqfail]', r.url(), r.failure()?.errorText));
try {
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  try {
    const result = await run(page);
    console.log('RUN OK:', JSON.stringify(result));
  } catch (e) {
    console.log('RUN ERR:', e.message);
  }
  console.log('FORM PRESENT:', await page.evaluate(() => !!document.querySelector('#mfaForm')));
} finally {
  await browser.close();
}
