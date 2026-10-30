import { chromium } from 'playwright';
const b = await chromium.launch({ executablePath: process.env.PW_EXECUTABLE });
const page = await b.newPage();
page.on('console', m => console.log('[console]', m.text()));
page.on('pageerror', e => console.log('[pageerror]', e.message));
await page.goto('http://localhost:8000', { waitUntil: 'domcontentloaded' });
await page.waitForTimeout(1500);
await page.fill('#loginForm input[name=username]', 'irumva');
await page.fill('#loginForm input[name=password]', 'irumvajc123');
await page.click('#loginForm button[type=submit]');
try { await page.waitForSelector('#mfaForm:not(.hidden)', { timeout: 8000 }); } catch { console.log('TIMEOUT waiting for MFA form'); }
const state = await page.evaluate(() => {
  const lf = document.querySelector('#loginForm'), mf = document.querySelector('#mfaForm');
  return { loginHidden: lf.className, mfaClass: mf.className, loginErr: document.querySelector('#loginErr').textContent, mfaErr: document.querySelector('#mfaErr').textContent, url: location.href };
});
console.log('STATE:', JSON.stringify(state));
await b.close();
