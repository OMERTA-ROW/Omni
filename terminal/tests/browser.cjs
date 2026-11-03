// Run with Playwright available in NODE_PATH; uses existing Chrome, no downloads.
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
(async () => {
 const browser = await chromium.launch({executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true});
 try {
 const page = await browser.newPage({viewport:{width:1440,height:1000}});
 const errors = [], requests = [];
 page.on('pageerror', e => errors.push(e.message));
 page.on('request', r => requests.push(r.url()));
 await page.goto(process.env.PREVIEW_URL || 'http://127.0.0.1:8765');
 await page.screenshot({path: process.env.SCREENSHOT_DIR + '/omni-desktop.png', fullPage:true});
 const command = page.locator('#command');
 async function run(value) { await command.fill(value); await command.press('Enter'); }
 await run('status');
 assert.match(await page.locator('#transcript').innerText(), /Agent transport: not connected/);
 await command.fill('unfinished'); await command.press('ArrowUp'); assert.equal(await command.inputValue(), 'status');
 await command.press('ArrowDown'); assert.equal(await command.inputValue(), 'unfinished');
 await page.locator('#new-session').click(); assert.equal(await command.inputValue(), '');
 await run('agents'); assert.match(await page.locator('#transcript').innerText(), /running status is unknown/);
 await page.locator('.session-button').first().click(); assert.equal(await command.inputValue(), 'unfinished');
 assert.doesNotMatch(await page.locator('#transcript').innerText(), /running status is unknown/);
 await run('<img src=x onerror=alert(1)>'); assert.equal(await page.locator('#transcript img').count(), 0);
 assert.match(await page.locator('#transcript').innerText(), /Nothing was executed/);
 await run('token=private-test-credential'); assert.doesNotMatch(await page.locator('#transcript').innerText(), /private-test-credential/);
 await page.locator('[data-view=history]').click(); assert.doesNotMatch(await page.locator('#transcript').innerText(), /private-test-credential|agents/);
 await page.locator('[data-view=logs]').click(); assert.match(await page.locator('#transcript').innerText(), /not CLI output/);
 await run('clear'); assert.match(await page.locator('#transcript').innerText(), /A quiet space/);
 for(let i=0;i<12;i++) await run('help');
 const before = await page.locator('.cosmos').boundingBox();
 await page.locator('#transcript').evaluate(el => el.scrollTop = 0);
 assert.deepEqual(await page.locator('.cosmos').boundingBox(), before);
 assert(await page.locator('#transcript').evaluate(el => el.scrollHeight > el.clientHeight));
 assert.equal(await page.evaluate(() => window.scrollY), 0);
 for(let i=0;i<6;i++) await page.locator('#new-session').click();
 assert(await page.locator('#new-session').isDisabled());
 assert.equal(await page.locator('.session-button').count(),8);
 await page.reload(); assert.equal(await page.locator('.session-button').count(),1);
 assert.equal(await page.locator('#history-count').innerText(),'0');
 await page.setViewportSize({width:390,height:844});
 assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
 await run('help'); assert(await command.isVisible());
 await page.reload();
 await page.screenshot({path:process.env.SCREENSHOT_DIR + '/omni-mobile.png',fullPage:true});
 assert.deepEqual(errors,[]);
 assert(requests.every(url => url.startsWith('http://127.0.0.1:8765/')));
 console.log('PASS: desktop/mobile layout, history draft recall, session isolation, disconnected status, text escaping, credential omission, clear/history, logs, independent scrolling, session cap, reload reset, no external requests, no browser errors.');
 } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode=1; });
