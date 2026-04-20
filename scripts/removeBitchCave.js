const fs = require('fs');

function removeBitchCave(filename) {
    if (!fs.existsSync(filename)) return;
    const entries = JSON.parse(fs.readFileSync(filename, 'utf8'));
    let changed = 0;

    entries.forEach(e => {
        if (e.customName && e.customName.toLowerCase() === 'bitch cave') {
            e.customName = null;
            changed++;
        }
    });

    if (changed > 0) {
        fs.writeFileSync(filename, JSON.stringify(entries, null, 2));
        console.log(`Reverted 'Bitch Cave' to default name in ${filename}`);
    } else {
        console.log(`No 'Bitch Cave' found in ${filename}`);
    }
}

removeBitchCave('data/fakeRoomEntries.json');
removeBitchCave('data/roomEntries.json');
