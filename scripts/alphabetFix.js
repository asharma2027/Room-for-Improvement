const fs = require('fs');

function fixAlphabet(filename) {
    if (!fs.existsSync(filename)) return;
    const entries = JSON.parse(fs.readFileSync(filename, 'utf8'));

    // 1. Find Shitbox Suite and fix its tags
    let shitbox = entries.find(e => e.customName && e.customName.toLowerCase() === 'shitbox suite');
    if (shitbox) {
        shitbox.tags = ["Tiny", "Cramped", "Dark"];
    }

    // 2. We need to identify any OTHER rooms in Salisbury that have customNames alphabetically before "Shitbox Suite"
    // To identify Salisbury rooms, we need to know their roomIds.
    // In our CSV, Salisbury room IDs are numbers from 41 to 50, but wait! We assigned Shitbox to ID 50.
    // Let's get all Salisbury room IDs.
    const roomsCsvData = fs.readFileSync('data/rooms.csv', 'utf8').split('\n');
    let salisburyIds = new Set();
    roomsCsvData.slice(1).forEach(row => {
        const parts = row.split(',');
        if (parts.length >= 4) {
            if (parts[1].trim() === 'Burton Judson' && parts[2].trim() === 'Salisbury') {
                salisburyIds.add(parts[0].trim());
            }
        }
    });

    entries.forEach(e => {
        if (salisburyIds.has(e.roomId) && e.customName && e.customName.toLowerCase() !== 'shitbox suite') {
            if (e.customName.toLowerCase().localeCompare('shitbox suite') < 0) {
                // Rename it so it comes after S
                console.log(`Renaming ${e.customName} to T-${e.customName} to keep Shitbox first`);
                e.customName = 'T-' + e.customName;
            }
        }
    });

    fs.writeFileSync(filename, JSON.stringify(entries, null, 2));
    console.log(`Fixed alphabet sorting in ${filename}`);
}

fixAlphabet('data/fakeRoomEntries.json');
fixAlphabet('data/roomEntries.json');
