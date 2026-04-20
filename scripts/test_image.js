const fs = require('fs');
const { createCanvas, loadImage } = require('canvas');

async function testImage(imgPath) {
    const img = await loadImage(imgPath);
    const cvs = createCanvas(img.width, img.height);
    const ctx = cvs.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const d = ctx.getImageData(0, 0, cvs.width, cvs.height).data;

    let minX = cvs.width, maxX = 0, minY = cvs.height, maxY = 0;
    let found = false;

    const marginX = Math.floor(cvs.width * 0.05); // Ignore UI edges
    const marginY = Math.floor(cvs.height * 0.05);
    const edgeThresholdX = marginX + 15;
    const edgeThresholdY = marginY + 15;

    for (let y = marginY; y < cvs.height - marginY; y += 4) {
        for (let x = marginX; x < cvs.width - marginX; x += 4) {
            const i = (y * cvs.width + x) * 4;
            const r = d[i], g = d[i + 1], b = d[i + 2];
            const maxCh = Math.max(r, g, b);
            const minCh = Math.min(r, g, b);

            if (maxCh - minCh > 40) {
                let isInnerMarker = false;
                if (r > g + 40 && r > b + 40 && g < 150) isInnerMarker = true;
                if (g > r + 40 && g > b + 40) isInnerMarker = true;

                if (!isInnerMarker) {
                    let whiteBgCount = 0;
                    let mapBgCount = 0;
                    const checkRadius = 8;
                    for (let ny = Math.max(0, y - checkRadius); ny <= Math.min(cvs.height - 1, y + checkRadius); ny += 2) {
                        for (let nx = Math.max(0, x - checkRadius); nx <= Math.min(cvs.width - 1, x + checkRadius); nx += 2) {
                            const ni = (ny * cvs.width + nx) * 4;
                            const nr = d[ni], ng = d[ni + 1], nb = d[ni + 2];
                            const nChroma = Math.max(nr, ng, nb) - Math.min(nr, ng, nb);
                            if (nChroma < 40 || (nr > 220 && ng > 220 && nb > 220)) {
                                if (nr > 245 && ng > 245 && nb > 245) whiteBgCount++;
                                else mapBgCount++;
                            }
                        }
                    }
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

    console.log(`Image: ${imgPath}`);
    console.log(`Size: ${cvs.width}x${cvs.height}`);
    console.log(`Margins: X=${marginX}, Y=${marginY}`);
    console.log(`Thresholds: X=${edgeThresholdX}, Y=${edgeThresholdY} | Max allowed X=${cvs.width - edgeThresholdX}, Max allowed Y=${cvs.height - edgeThresholdY}`);
    console.log(`Found: ${found}`);
    if (found) {
        console.log(`Bounds: minX=${minX}, maxX=${maxX}, minY=${minY}, maxY=${maxY}`);
        let cutOff = false;
        if (minX <= edgeThresholdX || maxX >= cvs.width - edgeThresholdX || minY <= edgeThresholdY || maxY >= cvs.height - edgeThresholdY) {
            cutOff = true;
        }
        console.log(`cutOff triggered: ${cutOff}`);
        console.log('---');
    }
}

async function main() {
    await testImage('/Users/arjun/Downloads/Room for Improvement/data/floorplans/010_BJ_Linn_Mathews_3_pdf.png');
    await testImage('/Users/arjun/Downloads/Room for Improvement/data/floorplans/011_BJ_Linn_Mathews_4_pdf.png');
    await testImage('/Users/arjun/Downloads/Room for Improvement/data/floorplans/018_BJ_Coulter_3_pdf.png');
}

main();
