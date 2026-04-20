const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());

async function run() {
    const browser = await puppeteer.launch({ headless: false, userDataDir: '../user_data', args: ['--start-maximized'] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1200, height: 800 });
    await page.goto('https://uchicago.app.box.com/s/auqa9etnfvrpvquabk4z9zbf0a1ksoh4', { waitUntil: 'domcontentloaded' });
    
    console.log('Please log in and open a PDF preview...');
    await page.waitForFunction(() => !!document.querySelector('.preview-content, .bp-content'), { timeout: 60000 }).catch(() => {});
    console.log('Preview open.');
    
    // allow time to settle
    await new Promise(r => setTimeout(r, 2000));
    
    const ui = await page.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button'));
        return btns.map(b => ({
            text: b.innerText.replace(/\n/g, ' '),
            title: b.title,
            aria: b.getAttribute('aria-label'),
            className: b.className
        })).filter(b => b.title?.toLowerCase().includes('zoom') || b.aria?.toLowerCase().includes('zoom') || b.className.toLowerCase().includes('zoom'));
    });
    console.log('Zoom buttons found:', ui);
    
    await browser.close();
}
run().catch(console.error);
