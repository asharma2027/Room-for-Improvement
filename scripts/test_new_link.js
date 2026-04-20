const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const path = require('path');

puppeteer.use(StealthPlugin());

const BOX_URL = 'https://uchicago.app.box.com/s/aty73l57ifk6jeojomm28liwce12v3kw/folder/137098542564';
const USER_DATA_DIR = path.join(__dirname, '../user_data');

async function run() {
    const browser = await puppeteer.launch({
        headless: 'new',
        defaultViewport: { width: 1920, height: 1080, deviceScaleFactor: 2 },
        userDataDir: USER_DATA_DIR
    });
    const page = await browser.newPage();

    console.log(`Navigating to ${BOX_URL}...`);
    await page.goto(BOX_URL, { waitUntil: 'networkidle2' });

    await page.screenshot({ path: path.join(__dirname, '../data/new_link_list.png') });
    console.log('Saved data/new_link_list.png');

    const firstPdf = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('[role="row"], .rt-tr-group'));
        for (const r of rows) {
            const text = r.innerText.split('\n')[0].trim();
            const id = r.getAttribute('data-resin-file_id') || r.getAttribute('data-item-id');
            if (text.toLowerCase().includes('.pdf') && id) {
                return { text, id };
            }
        }
        return null;
    });

    if (firstPdf) {
        console.log('Found PDF:', firstPdf.text);
        const selector = `[data-resin-file_id="${firstPdf.id}"]`;
        const row = await page.$(selector);
        if (row) {
            await page.evaluate(el => el.scrollIntoView({ block: 'center' }), row);
            const clicked = await page.evaluate(el => {
                const l = el.querySelector('a[data-resin-target="openfile"]');
                if (l) { l.click(); return true; }
                return false;
            }, row);
            if (!clicked) await row.click({ count: 2 });

            await new Promise(r => setTimeout(r, 6000));
            await page.screenshot({ path: path.join(__dirname, '../data/new_link_preview.png') });
            console.log('Saved data/new_link_preview.png');
        }
    } else {
        console.log('No PDF found');
        const html = await page.content();
        console.log("HTML length:", html.length);
    }

    await browser.close();
}
run();
