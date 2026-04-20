const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());

async function run() {
    console.log('Launching browser...');
    const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1400, height: 900 });
    console.log('Navigating...');
    await page.goto('https://uchicago.app.box.com/s/auqa9etnfvrpvquabk4z9zbf0a1ksoh4', { waitUntil: 'networkidle2' });
    await page.waitForTimeout(3000);
    await page.screenshot({ path: 'test_box.png' });
    console.log('Saved test_box.png');

    // Click the first PDF
    const firstRow = await page.$('.ReactVirtualized__Table__row');
    if (firstRow) {
        console.log('Clicking first row...');
        await firstRow.click({clickCount: 2});
        await page.waitForTimeout(5000);
        await page.screenshot({ path: 'test_box_preview.png' });
        console.log('Saved test_box_preview.png');
    }

    await browser.close();
}
run().catch(console.error);
