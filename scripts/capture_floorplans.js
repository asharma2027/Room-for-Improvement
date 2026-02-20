const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const fs = require('fs-extra');
const path = require('path');
const readline = require('readline');
const sizeOf = require('image-size');

puppeteer.use(StealthPlugin());

const BOX_URL = 'https://uchicago.app.box.com/s/auqa9etnfvrpvquabk4z9zbf0a1ksoh4';
const OUTPUT_DIR = path.join(__dirname, '../data/floorplans');
const USER_DATA_DIR = path.join(__dirname, '../user_data');

function askQuestion(query) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    return new Promise(resolve => rl.question(query, ans => {
        rl.close();
        resolve(ans);
    }));
}

async function cleanUp() {
    console.log('Performing cleanup...');
    await fs.ensureDir(OUTPUT_DIR);
    const files = await fs.readdir(OUTPUT_DIR);
    const groups = {};
    for (const f of files) {
        if (!f.match(/^\d{3}_/)) continue;
        const prefix = f.split('_')[0];
        if (!groups[prefix]) groups[prefix] = [];
        groups[prefix].push(f);
    }

    for (const prefix in groups) {
        const groupFiles = groups[prefix];
        const jpgs = groupFiles.filter(f => f.endsWith('.jpg') || f.endsWith('.jpeg'));
        const pngs = groupFiles.filter(f => f.endsWith('.png'));

        if (jpgs.length > 0 && pngs.length > 0) {
            for (const png of pngs) {
                console.log(`[Cleanup] Deleting screenshot (have blob): ${png}`);
                await fs.unlink(path.join(OUTPUT_DIR, png));
            }
        }
    }
    console.log('Cleanup complete.\n');
}

async function run() {
    await fs.ensureDir(OUTPUT_DIR);
    await fs.ensureDir(USER_DATA_DIR);

    await cleanUp();

    console.log('Launching browser...');
    const browser = await puppeteer.launch({
        headless: false,
        defaultViewport: null,
        args: ['--start-maximized'], // We will override viewport for the page
        userDataDir: USER_DATA_DIR
    });
    const pages = await browser.pages();
    if (pages.length > 1) {
        console.log(`Closing ${pages.length - 1} extra tabs...`);
        for (let i = 1; i < pages.length; i++) {
            await pages[i].close();
        }
    }
    const page = pages[0];

    // Set MASSIVE viewport to ensure "Fit to Screen" = High Resolution
    // 3000x3000px @ 2x pixel density = 6000x6000px effective canvas
    await page.setViewport({ width: 3000, height: 3000, deviceScaleFactor: 2 });

    console.log(`Navigating to ${BOX_URL}...`);
    await page.goto(BOX_URL, { waitUntil: 'domcontentloaded' });

    try {
        await page.waitForFunction(() => document.body.innerText.includes('.pdf'), { timeout: 5000 });
        console.log('Logged in.');
    } catch (e) {
        console.log('\nPlease log in to UChicago Box now.');
        await askQuestion('Press Enter when file list is visible...');
    }

    console.log('Starting collection...');

    let fileIndex = 1;
    let hasNextPage = true;
    const processedIdsThisSession = new Set();
    const retryQueue = [];
    const visitedUrls = new Set();

    while (hasNextPage) {
        const currentUrl = page.url();
        if (visitedUrls.has(currentUrl)) break;
        visitedUrls.add(currentUrl);

        console.log(`\n--- Processing Page: ${currentUrl} ---`);

        // Reset scroll to top
        await page.evaluate(() => {
            const container = document.querySelector('.ReactVirtualized__Grid__innerScrollContainer')?.parentElement || window;
            if (container.scrollTo) container.scrollTo(0, 0);
        });

        let scrolling = true;
        let noNewFilesCount = 0;

        while (scrolling) {
            // 1. SCAN for IDs and Names
            const visibleItems = await page.evaluate(() => {
                const rows = Array.from(document.querySelectorAll('[role="row"], .rt-tr-group'));
                return rows.map(r => {
                    const text = r.innerText.split('\n')[0].trim();
                    const id = r.getAttribute('data-resin-file_id') || r.getAttribute('data-item-id');
                    return { text, id };
                }).filter(item => item.text.toLowerCase().includes('.pdf') && item.id);
            });

            // 2. Identify new candidates
            const candidates = visibleItems.filter(item => !processedIdsThisSession.has(item.id));

            if (candidates.length === 0) {
                noNewFilesCount++;
                if (noNewFilesCount > 3) scrolling = false;
            } else {
                noNewFilesCount = 0;
            }

            // 3. Process Candidates
            for (const item of candidates) {
                processedIdsThisSession.add(item.id);
                const cleanName = item.text;

                // SKIP Existing
                // SKIP Existing - DISABLED to enforce high-res update
                /*
                const prefix = String(fileIndex).padStart(3, '0');
                const existing = await (async () => {
                    const list = await fs.readdir(OUTPUT_DIR);
                    return list.find(f => f.startsWith(prefix) && (f.endsWith('.jpg') || f.endsWith('.jpeg') || f.endsWith('.png')));
                })();

                if (existing) {
                    console.log(`Skipping ${cleanName} (have ${existing}).`);
                    fileIndex++;
                    continue;
                }
                */
                const prefix = String(fileIndex).padStart(3, '0');

                console.log(`Processing ${fileIndex}: ${cleanName} (ID: ${item.id})`);

                // FIND ELEMENT BY ID
                let rowElement = null;
                for (let attempt = 0; attempt < 3; attempt++) {
                    try {
                        const selector = `[data-resin-file_id="${item.id}"]`;
                        // Short wait on first attempt, no wait on retry
                        if (attempt === 0) await page.waitForSelector(selector, { timeout: 1000 }).catch(() => null);

                        rowElement = await page.$(selector);
                        if (rowElement) break;
                        await new Promise(r => setTimeout(r, 500)); // Wait for render
                    } catch (e) { }
                }

                if (!rowElement) {
                    console.log('  Element detached or scrolled out. Checking...');
                    continue;
                }

                // SCROLL INTO VIEW
                try {
                    await page.evaluate(el => el.scrollIntoView({ block: 'center', behavior: 'instant' }), rowElement);
                    await new Promise(r => setTimeout(r, 200));
                } catch (e) { }

                // CLICK
                let isPreviewOpen = false;
                try {
                    // Refetch by ID
                    const freshEl = await page.$(`[data-resin-file_id="${item.id}"]`);
                    if (freshEl) {
                        // Click link
                        const clicked = await page.evaluate(el => {
                            const l = el.querySelector('a[data-resin-target="openfile"]');
                            if (l) { l.click(); return true; }
                            return false;
                        }, freshEl);

                        if (!clicked) await freshEl.click({ count: 2 });

                        // Verify
                        for (let k = 0; k < 20; k++) { // Wait up to 10s (was 4s)
                            await new Promise(r => setTimeout(r, 500));
                            isPreviewOpen = await page.evaluate(() => !!document.querySelector('.preview-content, .bp-content-content, .bp-content'));
                            if (isPreviewOpen) break;
                        }

                        if (!isPreviewOpen) {
                            console.log('  Preview not open after click. Trying Enter key...');
                            // Last ditch: Enter key
                            await freshEl.focus();
                            await page.keyboard.press('Enter');
                            await new Promise(r => setTimeout(r, 3000));
                            isPreviewOpen = await page.evaluate(() => !!document.querySelector('.preview-content, .bp-content-content, .bp-content'));
                        }
                    } else {
                        console.log('  freshEl is null. Row might have been detached.');
                    }
                } catch (e) { console.log('  Click error:', e.message); }

                if (isPreviewOpen) {
                    /* BLOB EXTRACTION DISABLED - enforcing high-res screenshot
                    let imgSrc = null;
                     ... (blob logic commented out) ...
                    */

                    console.log('  Taking high-res screenshot...');
                    const safeName = cleanName.replace(/[^a-z0-9]/gi, '_').substring(0, 50);
                    const finalPath = path.join(OUTPUT_DIR, `${prefix}_${safeName}.png`);

                    // 1. Cleanup duplicates
                    try {
                        const allFiles = await fs.readdir(OUTPUT_DIR);
                        const duplicates = allFiles.filter(f => f.startsWith(prefix) && (f.endsWith('.jpg') || f.endsWith('.jpeg') || f.endsWith('.png')));
                        for (const dup of duplicates) {
                            if (dup !== path.basename(finalPath)) {
                                console.log(`  Deleting old/duplicate: ${dup}`);
                                await fs.unlink(path.join(OUTPUT_DIR, dup));
                            }
                        }
                    } catch (e) { console.log('  Cleanup warning:', e.message); }

                    // 2. CV-Based "Zoom-First & Expand" Logic
                    console.log('  Starting "Zoom-First & Expand" strategy...');

                    // Focus
                    try {
                        await page.focus('body');
                        await page.click('.preview-content, .bp-content', { delay: 100 }).catch(() => { });
                    } catch (e) { }

                    // A. Reset view (Zoom Out) to get baseline
                    console.log('    Resetting view to scout...');
                    const zoomOutBtn = await page.$('button[title="Zoom out"], button[aria-label="Zoom out"]');
                    if (zoomOutBtn) {
                        for (let k = 0; k < 12; k++) { await zoomOutBtn.click(); await new Promise(r => setTimeout(r, 100)); }
                    } else {
                        for (let k = 0; k < 12; k++) {
                            await page.keyboard.down('Control'); await page.keyboard.press('-'); await page.keyboard.up('Control');
                            await new Promise(r => setTimeout(r, 100));
                        }
                    }
                    await new Promise(r => setTimeout(r, 1000));

                    // B. Scout Screenshot & Analyze
                    const scoutB64 = await page.screenshot({ encoding: 'base64' });

                    // Analyze in browser
                    const bounds = await page.evaluate(async (b64) => {
                        return new Promise((resolve) => {
                            const img = new Image();
                            img.onload = () => {
                                const cvs = document.createElement('canvas');
                                cvs.width = img.width; cvs.height = img.height;
                                const ctx = cvs.getContext('2d');
                                ctx.drawImage(img, 0, 0);
                                const idata = ctx.getImageData(0, 0, cvs.width, cvs.height);
                                const d = idata.data;
                                let minX = cvs.width, maxX = 0, minY = cvs.height, maxY = 0;
                                let found = false;

                                // Ignore outer 5% to avoid borders
                                const marginX = Math.floor(cvs.width * 0.05);
                                const marginY = Math.floor(cvs.height * 0.05);

                                for (let y = marginY; y < cvs.height - marginY; y += 2) {
                                    for (let x = marginX; x < cvs.width - marginX; x += 2) {
                                        const i = (y * cvs.width + x) * 4;
                                        const r = d[i], g = d[i + 1], b = d[i + 2];
                                        const maxCh = Math.max(r, g, b);
                                        const minCh = Math.min(r, g, b);
                                        // Diff > 40
                                        if ((maxCh - minCh) > 40) {
                                            if (x < minX) minX = x;
                                            if (x > maxX) maxX = x;
                                            if (y < minY) minY = y;
                                            if (y > maxY) maxY = y;
                                            found = true;
                                        }
                                    }
                                }

                                if (!found) resolve(null);
                                else resolve({
                                    x: minX, y: minY,
                                    w: maxX - minX, h: maxY - minY,
                                    imgW: cvs.width, imgH: cvs.height
                                });
                            };
                            img.src = `data:image/png;base64,${b64}`;
                        });
                    }, scoutB64);

                    const scrollContainerSelector = '.bp-doc-document, .preview-content';

                    if (!bounds) {
                        console.log('    No colored polygon detected during scout. Using standard high zoom fallback.');
                        // Fallback
                        for (let z = 0; z < 15; z++) {
                            await page.keyboard.down('Control'); await page.keyboard.press('='); await page.keyboard.up('Control');
                        }
                    } else {
                        // Check if coverage is effectively "whole page" (detection drift) or "specific house"
                        const coverage = (bounds.w * bounds.h) / (bounds.imgW * bounds.imgH);
                        console.log(`    Scout Polygon: ${Math.round(bounds.w)}x${Math.round(bounds.h)} (Cov: ${(coverage * 100).toFixed(1)}%)`);

                        // C. Calculate Relative Metrics
                        // We need to know where the polygon is relative to the *Scroll Content*
                        // At "fit to page" (scout), the scrollContent ~= viewport usually.
                        // But safest is to get current scrollWidth.
                        const scoutDims = await page.evaluate((sel) => {
                            const el = document.querySelector(sel);
                            return el ? { w: el.scrollWidth, h: el.scrollHeight } : { w: window.innerWidth, h: window.innerHeight };
                        }, scrollContainerSelector);

                        // Assuming screenshot bounds map linearly to scroll dimensions (if fit)
                        // Ratio of Polygon Width to Total Image Width
                        // Note: bounds.w is in *viewport pixels*. scoutDims.w is *scroll pixels*.
                        // If "fit to page", viewport ~= scroll w.
                        // Let's assume linearity: PolyRatio = bounds.w / bounds.imgW;
                        let polyRatioW = bounds.w / bounds.imgW;
                        let polyRatioH = bounds.h / bounds.imgH;

                        // Center %
                        const cxPct = (bounds.x + bounds.w / 2) / bounds.imgW;
                        const cyPct = (bounds.y + bounds.h / 2) / bounds.imgH;

                        // D. FORCE HIGH FIDELITY ZOOM
                        // User wants App Zoom to be high (e.g. 250%).
                        // 15 clicks is a safe bet for "High Fidelity".
                        console.log('    Forcing High-Fidelity App Zoom (15 steps)...');
                        const zoomInBtn = await page.$('button[title="Zoom in"], button[aria-label="Zoom in"]');

                        for (let z = 0; z < 15; z++) {
                            if (zoomInBtn) await zoomInBtn.click();
                            else {
                                await page.keyboard.down('Control'); await page.keyboard.press('='); await page.keyboard.up('Control');
                            }
                            await new Promise(r => setTimeout(r, 200));
                        }
                        await new Promise(r => setTimeout(r, 1000)); // Settlement

                        // E. Adapative Resize
                        // Measure new massive content size
                        const highResDims = await page.evaluate((sel) => {
                            const el = document.querySelector(sel);
                            return el ? { w: el.scrollWidth, h: el.scrollHeight } : { w: 5000, h: 5000 };
                        }, scrollContainerSelector);

                        console.log(`    High-Res Dimensions: ${highResDims.w}x${highResDims.h}`);

                        // Calculate Target Viewport Size
                        // NewPolyWidth = ContentTotalWidth * PolyRatio
                        const targetW = Math.ceil(highResDims.w * polyRatioW * 1.15); // 15% padding
                        const targetH = Math.ceil(highResDims.h * polyRatioH * 1.15);

                        console.log(`    Resizing Viewport to fit House: ${targetW}x${targetH}`);
                        await page.setViewport({ width: targetW, height: targetH, deviceScaleFactor: 2 });
                        await new Promise(r => setTimeout(r, 500));

                        // F. Pan to Center
                        console.log(`    Panning to Center (${(cxPct * 100).toFixed(1)}%, ${(cyPct * 100).toFixed(1)}%)...`);
                        await page.evaluate((sel, cx, cy) => {
                            const el = document.querySelector(sel);
                            if (el) {
                                const targetLeft = (el.scrollWidth * cx) - (window.innerWidth / 2);
                                const targetTop = (el.scrollHeight * cy) - (window.innerHeight / 2);
                                el.scrollTo(targetLeft, targetTop);
                            }
                        }, scrollContainerSelector, cxPct, cyPct);
                    }

                    // Wait for final render
                    await new Promise(r => setTimeout(r, 2000));

                    // 3. Take Screenshot
                    try {
                        const previewEl = await page.$('.preview-content, .bp-content-content, .bp-content');
                        if (previewEl) {
                            await previewEl.screenshot({ path: finalPath });
                            console.log(`  Saved high-res screenshot: ${finalPath}`);
                        } else {
                            // Fallback to page screenshot if element not found (since we set viewport, page screenshot is fine)
                            await page.screenshot({ path: finalPath });
                            console.log(`  Saved high-res screenshot (full page): ${finalPath}`);
                        }
                    } catch (e) {
                        console.error('  Screenshot error:', e.message);
                        retryQueue.push({ index: fileIndex, name: cleanName, reason: "Screenshot error" });
                    }

                    await page.keyboard.press('Escape');
                    await new Promise(r => setTimeout(r, 1000));
                    // Check close
                    const stillOpen = await page.evaluate(() => !!document.querySelector('.preview-content, .bp-content-content, .bp-content'));
                    if (stillOpen) {
                        const closeBtn = await page.$('button[aria-label="Close"]');
                        if (closeBtn) await closeBtn.click();
                    }
                } else {
                    console.log('  Failed to open preview. Saving debug info...');
                    const debugPrefix = `failure_${item.id}`;
                    await page.screenshot({ path: path.join(OUTPUT_DIR, `${debugPrefix}.png`) });
                    const html = await page.content();
                    await fs.writeFile(path.join(OUTPUT_DIR, `${debugPrefix}.html`), html);
                    console.log(`  Saved ${debugPrefix}.png and .html`);

                    retryQueue.push({ index: fileIndex, name: cleanName, reason: "Preview failed" });
                }

                fileIndex++;
            } // End of for(item of candidates)

            // Scroll Logic (inside while loop)
            noNewFilesCount++;
            if (noNewFilesCount > 5) scrolling = false;

            // Scroll down
            await page.evaluate(() => {
                const container = document.querySelector('.ReactVirtualized__Grid__innerScrollContainer')?.parentElement || window;
                container.scrollBy(0, 600);
            });
            await new Promise(r => setTimeout(r, 2000));
        } // End of while(scrolling)

        // Next page
        try {
            const currentUrlObj = new URL(page.url());
            const currentPageNum = parseInt(currentUrlObj.searchParams.get('page')) || 1;
            const targetPageNum = currentPageNum + 1;
            const nextBtn = await page.$(`a[href*="page=${targetPageNum}"]`);
            if (nextBtn) {
                console.log('Next page...');
                await nextBtn.click();
                await new Promise(r => setTimeout(r, 5000));
            } else {
                console.log('No next page.');
                hasNextPage = false;
            }
        } catch (e) { hasNextPage = false; }
    } // End of PAGE loop (which is missing its opening 'while(hasNextPage)'? No, it's inside `run`).
    // Wait, let's check the structure again.
    // function run() {
    //    while(hasNextPage) {
    //       ...
    //    }
    //    if (retry) ...
    //    close
    // }

    // The previous edits might have messed up `hasNextPage`.
    // Let's just fix the end block assuming the `while` loop is still open above.
    // Actually, line 438 was `} // End of while(scrolling)`. 
    // The `while(hasNextPage)` loop usually wraps everything from line ~100.

    // Let's assume the context around line 455 needs to close the `while(hasNextPage)` loop.

    if (retryQueue.length > 0) {
        console.log('\n=== FAILURES ===');
        retryQueue.forEach(f => console.log(`[${f.index}] ${f.name} - ${f.reason}`));
    }
    console.log('Done.');
    await browser.close();
} // End of run()

run().catch(console.error);
