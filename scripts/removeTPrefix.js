const fs = require('fs');

function removeTPrefix(filename) {
    if (!fs.existsSync(filename)) return;
    const entries = JSON.parse(fs.readFileSync(filename, 'utf8'));
    let changed = 0;

    entries.forEach(e => {
        if (e.customName && e.customName.startsWith('T-')) {
            e.customName = e.customName.substring(2);
            changed++;
        }
    });

    if (changed > 0) {
        fs.writeFileSync(filename, JSON.stringify(entries, null, 2));
        console.log(`Removed 'T-' prefix from ${changed} names in ${filename}`);
    } else {
        console.log(`No 'T-' prefixes found in ${filename}`);
    }
}

removeTPrefix('data/fakeRoomEntries.json');
removeTPrefix('data/roomEntries.json');
