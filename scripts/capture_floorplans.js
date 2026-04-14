const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const fs = require('fs-extra');
const path = require('path');
const readline = require('readline');
const sizeOf = require('image-size');

puppeteer.use(StealthPlugin());

const BOX_URL = 'https://uchicago.box.com/s/75o86h1yl67bwr8xfnokjkpz17uyb4xy';
const DORM_NAME = 'Woodlawn';
const OUTPUT_DIR = path.join(__dirname, '../data/floorplans', DORM_NAME, 'raw');
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
        protocolTimeout: 180000,
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

    // Standard 1080p viewport to ensure final image size is predictable and not filled with grey space
    await page.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 2 });

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
                // SKIP Existing
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

                    let fallbackB64 = null;
                    try {
                        console.log('  Taking safe fallback screenshot...');
                        fallbackB64 = await Promise.race([
                            page.screenshot({ encoding: 'base64', type: 'png' }),
                            new Promise((_, r) => setTimeout(() => r(null), 5000))
                        ]);
                    } catch (e) {
                        console.log('    Fallback screenshot failed:', e.message);
                    }

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

                    // Focus and hover to ensure UI appears
                    try {
                        await Promise.race([
                            (async () => {
                                const pv = await page.$('.preview-content, .bp-content');
                                if (pv) {
                                    const box = await pv.boundingBox();
                                    if (box) {
                                        await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2).catch(() => { });
                                    }
                                    await pv.click({ delay: 100 }).catch(() => { });
                                }
                            })(),
                            new Promise((_, rej) => setTimeout(() => rej(new Error('UI focus timeout')), 5000))
                        ]);
                    } catch (e) { }

                    // A. Scout Screenshot & Analyze (Default "Fit" View)
                    console.log('    Taking scout screenshot from default fit view...');
                    await new Promise(r => setTimeout(r, 1000));

                    let tabDead = false;
                    let skipRest = false;

                    const client = await Promise.race([
                        page.target().createCDPSession(),
                        new Promise((_, rej) => setTimeout(() => rej(new Error('Scout CDP Create Timeout')), 10000))
                    ]).catch(e => {
                        console.log(`      [DEBUG] Error: ${e.message}`);
                        tabDead = true;
                        return null;
                    });

                    let scoutB64 = null;
                    if (client) {
                        const scoutDataRes = await Promise.race([
                            client.send('Page.captureScreenshot', { format: 'jpeg', quality: 50 }),
                            new Promise((_, rej) => setTimeout(() => rej(new Error('Scout CDP Cap Timeout')), 15000))
                        ]).catch(async e => {
                            console.log(`      [DEBUG] Scout Screenshot Error: ${e.message}`);
                            tabDead = true;
                            await client.detach().catch(() => { });
                            return null;
                        });
                        if (scoutDataRes) {
                            scoutB64 = scoutDataRes.data;
                            fallbackB64 = scoutB64; // Promote fallback to the better scout screenshot
                            await client.detach().catch(() => { });
                        }
                    }

                    if (tabDead) {
                        console.error('  Screenshot error: Chromium renderer completely dead on scout screenshot');
                        retryQueue.push({ index: fileIndex, name: cleanName, reason: "Chromium renderer completely dead" });
                        skipRest = true;
                    }

                    // Analyze in browser
                    let bounds = null;
                    if (scoutB64 && !skipRest) {
                        bounds = await Promise.race([
                            page.evaluate(async (b64) => {
                                return new Promise((resolve) => {
                                    const img = new Image();
                                    img.onload = () => {
                                        const cvs = document.createElement('canvas');
                                        // Scale down for performance (extra scaling for large floorplans)
                                        const scale = 0.25;
                                        cvs.width = Math.floor(img.width * scale);
                                        cvs.height = Math.floor(img.height * scale);
                                        const ctx = cvs.getContext('2d');
                                        ctx.drawImage(img, 0, 0, cvs.width, cvs.height);
                                        const idata = ctx.getImageData(0, 0, cvs.width, cvs.height);
                                        const d = idata.data;
                                        let minX = cvs.width, maxX = 0, minY = cvs.height, maxY = 0;
                                        let found = false;

                                        // Ignore outer 5% to avoid borders
                                        const marginX = Math.floor(cvs.width * 0.05);
                                        const marginY = Math.floor(cvs.height * 0.05);

                                        for (let y = marginY; y < cvs.height - marginY; y += 4) {
                                            for (let x = marginX; x < cvs.width - marginX; x += 4) {
                                                const i = (y * cvs.width + x) * 4;
                                                const r = d[i], g = d[i + 1], b = d[i + 2];
                                                const maxCh = Math.max(r, g, b);
                                                const minCh = Math.min(r, g, b);
                                                const chroma = maxCh - minCh;

                                                // Ignore black/grey (chroma <= 40)
                                                if (chroma > 40) {
                                                    // DO NOT Filter out red/green for Max Palevsky (rooms are these colors)
                                                    let isInnerMarker = false;

                                                    if (!isInnerMarker) {
                                                        // Check if it's text inside a white label box by measuring background density
                                                        let whiteBgCount = 0;
                                                        let mapBgCount = 0;
                                                        const checkRadius = 8;
                                                        for (let ny = Math.max(0, y - checkRadius); ny <= Math.min(cvs.height - 1, y + checkRadius); ny += 4) {
                                                            for (let nx = Math.max(0, x - checkRadius); nx <= Math.min(cvs.width - 1, x + checkRadius); nx += 4) {
                                                                const ni = (ny * cvs.width + nx) * 4;
                                                                const nr = d[ni], ng = d[ni + 1], nb = d[ni + 2];
                                                                const nChroma = Math.max(nr, ng, nb) - Math.min(nr, ng, nb);
                                                                // Tally Background pixels
                                                                if (nChroma < 40 || (nr > 220 && ng > 220 && nb > 220)) {
                                                                    if (nr > 245 && ng > 245 && nb > 245) whiteBgCount++;
                                                                    else mapBgCount++;
                                                                }
                                                            }
                                                        }
                                                        // Text labels are entirely engulfed in white. Polygons live on map geometry.
                                                        let isTextLabel = (whiteBgCount > 5 && mapBgCount < whiteBgCount / 2);

                                                        if (!isTextLabel) {
                                                            if (x < minX) minX = x;
                                                            if (x > maxX) maxX = x;
                                                            if (y < minY) minY = y;
                                                            if (y > maxY) maxY = y;
                                                            found = true;
                                                        }
                                                    }
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
                                    img.src = `data:image/jpeg;base64,${b64}`;
                                });
                            }, scoutB64),
                            new Promise((_, rej) => setTimeout(() => rej(new Error('Page Evaluate hung!')), 10000))
                        ]).catch(e => {
                            console.log(`      [DEBUG] Error in prep page evaluate: ${e.message}`);
                            return null;
                        });
                    }

                    const scrollContainerSelector = '.bp-doc-document, .preview-content';

                    if (!bounds && !skipRest) {
                        console.log('    No colored polygon detected during scout. Using standard high zoom fallback.');
                        const getZoomInBtn = () => page.evaluateHandle(() => {
                            const btns = Array.from(document.querySelectorAll('button'));
                            return btns.find(b => {
                                const t = (b.title || '').toLowerCase();
                                const a = (b.getAttribute('aria-label') || '').toLowerCase();
                                return t.includes('zoom in') || a.includes('zoom in') || b.className.toLowerCase().includes('zoom-in');
                            });
                        });

                        console.log("    Triggering UI Zoom In button (10 clicks)...");
                        for (let z = 0; z < 10; z++) {
                            const inBtn = await getZoomInBtn();
                            if (await inBtn.evaluate(b => !!b)) await inBtn.click();
                            else {
                                await page.mouse.move(500 + z * 5, 500); // nudge mouse to keep UI awake
                            }
                            await new Promise(r => setTimeout(r, 400));
                        }
                    } else if (!skipRest) {
                        // Check if coverage is effectively "whole page" (detection drift) or "specific house"
                        const coverage = (bounds.w * bounds.h) / (bounds.imgW * bounds.imgH);
                        console.log(`    Scout Polygon: ${Math.round(bounds.w)}x${Math.round(bounds.h)} (Cov: ${(coverage * 100).toFixed(1)}%)`);

                        // D. INCREMENTAL ZOOM WITH PREP CHECKS
                        console.log('    Starting iterative zoom-in logic...');
                        const getZoomBtn = (type) => page.evaluateHandle((t) => {
                            const btns = Array.from(document.querySelectorAll('button'));
                            return btns.find(b => {
                                const title = (b.title || '').toLowerCase();
                                const a = (b.getAttribute('aria-label') || '').toLowerCase();
                                return title.includes(t) || a.includes(t) || b.className.toLowerCase().includes(t.replace(' ', '-'));
                            });
                        }, type);

                        for (let z = 0; z < 15; z++) {
                            // 1. Take prep screenshot
                            const prepClient = await Promise.race([
                                page.target().createCDPSession(),
                                new Promise((_, rej) => setTimeout(() => rej(new Error('Prep CDP Create Timeout')), 10000))
                            ]).catch(() => null);

                            if (!prepClient) {
                                console.log(`      [DEBUG] Failed to create prep client on zoom ${z}, breaking zoom loop.`);
                                break;
                            }

                            const prepDataRes = await Promise.race([
                                prepClient.send('Page.captureScreenshot', { format: 'jpeg', quality: 50 }),
                                new Promise((_, rej) => setTimeout(() => rej(new Error('Prep CDP Cap Timeout')), 10000))
                            ]).catch(async e => {
                                console.log(`      [DEBUG] Prep Screenshot Error: ${e.message}`);
                                await prepClient.detach().catch(() => { });
                                return null;
                            });

                            if (!prepDataRes) break;

                            const prepB64 = prepDataRes.data;
                            await prepClient.detach();

                            // 2. Analyze prep screenshot
                            const prepAnalysis = await Promise.race([
                                page.evaluate(async (b64) => {
                                    return new Promise((resolve) => {
                                        const img = new Image();
                                        img.onload = () => {
                                            const cvs = document.createElement('canvas');
                                            // Scale down for performance
                                            const scale = 0.25;
                                            cvs.width = Math.floor(img.width * scale);
                                            cvs.height = Math.floor(img.height * scale);
                                            const ctx = cvs.getContext('2d');
                                            ctx.drawImage(img, 0, 0, cvs.width, cvs.height);
                                            const d = ctx.getImageData(0, 0, cvs.width, cvs.height).data;

                                            let minX = cvs.width, maxX = 0, minY = cvs.height, maxY = 0;
                                            let found = false;

                                            const marginX = Math.floor(cvs.width * 0.05); // Ignore UI edges
                                            const marginY = Math.floor(cvs.height * 0.05);
                                            const edgeThresholdX = marginX + 70;
                                            const edgeThresholdY = marginY + 70;

                                            for (let y = marginY; y < cvs.height - marginY; y += 4) {
                                                for (let x = marginX; x < cvs.width - marginX; x += 4) {
                                                    const i = (y * cvs.width + x) * 4;
                                                    const r = d[i], g = d[i + 1], b = d[i + 2];
                                                    const maxCh = Math.max(r, g, b);
                                                    const minCh = Math.min(r, g, b);

                                                    if (maxCh - minCh > 40) {
                                                        // DO NOT filter red/green for Max Palevsky
                                                        let isInnerMarker = false;

                                                        if (!isInnerMarker) {
                                                            // Check if it's text inside a white label box by measuring background density
                                                            let whiteBgCount = 0;
                                                            let mapBgCount = 0;
                                                            const checkRadius = 8;
                                                            for (let ny = Math.max(0, y - checkRadius); ny <= Math.min(cvs.height - 1, y + checkRadius); ny += 4) {
                                                                for (let nx = Math.max(0, x - checkRadius); nx <= Math.min(cvs.width - 1, x + checkRadius); nx += 4) {
                                                                    const ni = (ny * cvs.width + nx) * 4;
                                                                    const nr = d[ni], ng = d[ni + 1], nb = d[ni + 2];
                                                                    const nChroma = Math.max(nr, ng, nb) - Math.min(nr, ng, nb);
                                                                    // Tally Background pixels
                                                                    if (nChroma < 40 || (nr > 220 && ng > 220 && nb > 220)) {
                                                                        if (nr > 245 && ng > 245 && nb > 245) whiteBgCount++;
                                                                        else mapBgCount++;
                                                                    }
                                                                }
                                                            }
                                                            // Text labels are entirely engulfed in white. Polygons live on map geometry.
                                                            let isTextLabel = (whiteBgCount > 5 && mapBgCount < whiteBgCount / 2);

                                                            if (!isTextLabel) {
                                                                if (x < minX) minX = x;
                                                                if (x > maxX) maxX = x;
                                                                if (y < minY) minY = y;
                                                                if (y > maxY) maxY = y;
                                                                found = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            if (!found) {
                                                resolve({ isCutOff: false, found: false });
                                            } else {
                                                let cutOff = false;
                                                if (minX <= edgeThresholdX || maxX >= cvs.width - edgeThresholdX || minY <= edgeThresholdY || maxY >= cvs.height - edgeThresholdY) {
                                                    cutOff = true;
                                                }
                                                resolve({ isCutOff: cutOff, found: true });
                                            }
                                        };
                                        img.src = `data:image/jpeg;base64,${b64}`;
                                    });
                                }, prepB64),
                                new Promise((_, rej) => setTimeout(() => rej(new Error('Prep evaluate Timeout')), 10000))
                            ]).catch(e => {
                                console.log(`      [DEBUG] Error analyzing prep: ${e.message}`);
                                return { isCutOff: false, found: false, error: true };
                            });

                            if (prepAnalysis.error) {
                                console.log("      Error in prep analysis. Breaking zoom loop.");
                                break;
                            }

                            if (!prepAnalysis.found) {
                                console.log("      No polygon found in prep check. Breaking zoom loop.");
                                if (z > 0) {
                                    console.log("      Polygon pushed off-screen. Reverting one zoom level...");
                                    await page.evaluate(() => {
                                        const btns = Array.from(document.querySelectorAll('button'));
                                        const outBtn = btns.find(b => {
                                            const title = (b.title || '').toLowerCase();
                                            const a = (b.getAttribute('aria-label') || '').toLowerCase();
                                            return title.includes('zoom out') || a.includes('zoom out') || b.className.toLowerCase().includes('zoom-out');
                                        });
                                        if (outBtn) outBtn.click();
                                    }).catch(() => { });
                                    await new Promise(r => setTimeout(r, 1500));
                                }
                                break;
                            }

                            if (prepAnalysis.isCutOff) {
                                console.log(`      Polygon boundary clipped screen edge at zoom step ${z}. Reverting one zoom level...`);
                                if (z > 0) {
                                    await Promise.race([
                                        page.evaluate(() => {
                                            const btns = Array.from(document.querySelectorAll('button'));
                                            const outBtn = btns.find(b => {
                                                const title = (b.title || '').toLowerCase();
                                                const a = (b.getAttribute('aria-label') || '').toLowerCase();
                                                return title.includes('zoom out') || a.includes('zoom out') || b.className.toLowerCase().includes('zoom-out');
                                            });
                                            if (outBtn) outBtn.click();
                                        }).catch(() => { }),
                                        new Promise(r => setTimeout(r, 2000))
                                    ]);
                                    await new Promise(r => setTimeout(r, 1500));
                                }
                                break;
                            }

                            // Update fallback to the highest successful, fully-in-bounds zoom level screenshot!
                            console.log(`      [DEBUG] Saving highest safe zoom level (Step ${z}) as fallback...`);
                            fallbackB64 = prepB64;

                            // 3. Polygon is completely in view, safe to zoom in!
                            console.log(`      Polygon fully in view. Zooming in (Step ${z + 1}/15)...`);
                            const clickedIn = await Promise.race([
                                page.evaluate(() => {
                                    const btns = Array.from(document.querySelectorAll('button'));
                                    const inBtn = btns.find(b => {
                                        const title = (b.title || '').toLowerCase();
                                        const a = (b.getAttribute('aria-label') || '').toLowerCase();
                                        return title.includes('zoom in') || a.includes('zoom in') || b.className.toLowerCase().includes('zoom-in');
                                    });
                                    if (inBtn) {
                                        inBtn.click();
                                        return true;
                                    }
                                    return false;
                                }).catch(() => false),
                                new Promise(r => setTimeout(() => r(false), 2000))
                            ]);

                            if (!clickedIn) {
                                await page.mouse.move(500 + z * 5, 500).catch(() => { }); // Wake up UI
                            }
                            await new Promise(r => setTimeout(r, 800)); // Settlement time between zooms
                        }
                    }

                    console.log(`      [DEBUG] Exited zoom loop`);
                    // Wait for final render
                    await new Promise(r => setTimeout(r, 2000));

                    // 3. Take Screenshot
                    try {
                        if (skipRest) {
                            console.log(`      [DEBUG] Saving fallback image to perfectly skip this broken file...`);
                            if (fallbackB64) {
                                const ext = fallbackB64.startsWith('iVBORw0K') ? '.png' : '.jpeg'; // Infer Type
                                const fallbackPath = finalPath.replace('.png', ext);
                                await fs.writeFile(fallbackPath, Buffer.from(fallbackB64, 'base64')).catch(() => { });
                            } else {
                                const emptyPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');
                                await fs.writeFile(finalPath, emptyPng).catch(() => { });
                            }
                            throw new Error("Skipped due to dead renderer");
                        }

                        console.log(`      [DEBUG] Creating final CDP Session...`);
                        const finalClient = await Promise.race([
                            page.target().createCDPSession(),
                            new Promise((_, rej) => setTimeout(() => rej(new Error('CDP Create Timeout')), 10000))
                        ]);

                        console.log(`      [DEBUG] Final CDP Session created. Sending capture request with 30s timeout...`);
                        const { data: finalB64 } = await Promise.race([
                            finalClient.send('Page.captureScreenshot', { format: 'jpeg', quality: 50 }),
                            new Promise((_, rej) => setTimeout(() => rej(new Error('CDP Screenshot Timeout')), 30000))
                        ]);
                        await finalClient.detach().catch(() => { });
                        const finalPathJpeg = finalPath.replace('.png', '.jpeg');
                        await fs.writeFile(finalPathJpeg, Buffer.from(finalB64, 'base64'));
                        console.log(`  Saved high-res screenshot (CDP): ${finalPathJpeg}`);
                    } catch (e) {
                        console.error('  Screenshot error:', e.message);
                        retryQueue.push({ index: fileIndex, name: cleanName, reason: "Screenshot error" });
                    }

                    let closed = false;
                    for (let escAttempt = 0; escAttempt < 2; escAttempt++) {
                        await Promise.race([
                            page.keyboard.press('Escape').catch(() => { }),
                            new Promise(r => setTimeout(r, 2000))
                        ]);
                        await new Promise(r => setTimeout(r, 1000));

                        // Use Promise.race to prevent dead renderer from blocking indefinitely
                        const stillOpen = await Promise.race([
                            page.evaluate(() => !!document.querySelector('.preview-content, .bp-content-content, .bp-content')).catch(() => false),
                            new Promise(r => setTimeout(() => r(true), 2000)) // Act as if still open if it hangs
                        ]);

                        if (!stillOpen) {
                            closed = true;
                            break;
                        }
                    }

                    if (!closed) {
                        const closeBtn = await Promise.race([
                            page.$('button[aria-label="Close"]').catch(() => null),
                            new Promise(r => setTimeout(() => r(null), 2000))
                        ]);
                        if (closeBtn) {
                            await closeBtn.click().catch(() => { });
                        } else {
                            console.log("  Tab appears completely hung. Reloading page to recover...");
                            const reloaded = await Promise.race([
                                page.reload({ waitUntil: 'domcontentloaded' }).then(() => true).catch(() => false),
                                new Promise(r => setTimeout(() => r(false), 5000))
                            ]);
                            if (!reloaded) {
                                console.log("      [CRITICAL] page.reload() completely hung! The Chromium renderer is unrecoverable. Exiting script to force a fresh restart...");
                                console.log(`      [DEBUG] Saving fallback image to perfectly skip this broken file...`);
                                if (fallbackB64) {
                                    const ext = fallbackB64.startsWith('iVBORw0K') ? '.png' : '.jpeg';
                                    const fallbackPath = finalPath.replace('.png', ext);
                                    await fs.writeFile(fallbackPath, Buffer.from(fallbackB64, 'base64')).catch(() => { });
                                } else {
                                    const emptyPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');
                                    await fs.writeFile(finalPath, emptyPng).catch(() => { });
                                }
                                process.exit(1);
                            }
                            break;
                        }
                    }
                } else {
                    console.log('  Failed to open preview. Saving debug info...');
                    const debugPrefix = `failure_${item.id}`;
                    await page.screenshot({ path: path.join(OUTPUT_DIR, `${debugPrefix}.png`) }).catch(() => { });
                    const html = await Promise.race([
                        page.content().catch(() => ''),
                        new Promise(r => setTimeout(() => r(''), 2000))
                    ]);
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
            await Promise.race([
                page.evaluate(() => {
                    const container = document.querySelector('.ReactVirtualized__Grid__innerScrollContainer')?.parentElement || window;
                    container.scrollBy(0, 600);
                }).catch(() => { }),
                new Promise(r => setTimeout(r, 2000))
            ]);
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
                await page.evaluate(el => el.click(), nextBtn).catch(() => { });

                // Wait for URL to actually change
                for (let k = 0; k < 10; k++) {
                    await new Promise(r => setTimeout(r, 500));
                    if (page.url().includes(`page=${targetPageNum}`)) break;
                }
            } else {
                console.log('No next page.');
                hasNextPage = false;
            }
        } catch (e) { hasNextPage = false; }
    } // End of while(hasNextPage)

    if (retryQueue.length > 0) {
        console.log('\n=== FAILURES ===');
        retryQueue.forEach(f => console.log(`[${f.index}] ${f.name} - ${f.reason}`));
    }
    console.log('Done.');
    await browser.close();
} // End of run()

run().catch(console.error);
