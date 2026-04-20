const fs = require('fs');

function fixShitboxReal(filename) {
    if (!fs.existsSync(filename)) return;
    const entries = JSON.parse(fs.readFileSync(filename, 'utf8'));

    const floorplanCsv = fs.readFileSync('data/floorplans/Burton-Judson/colored_rooms.csv', 'utf8').split('\n');
    let minRoomNum = Infinity;
    let minRoomId = "";

    floorplanCsv.slice(1).forEach(row => {
        const parts = row.split(',');
        if (parts.length < 5) return;
        
        const roomNumStr = parts[0].trim();
        const floorStr = parts[1].trim();
        const dormStr = parts[2].trim();
        const houseStr = parts[3].trim();
        
        if (dormStr === 'Burton-Judson' && houseStr === 'Salisbury') {
            const num = parseInt(roomNumStr.replace(/\D/g, ''));
            if (!isNaN(num) && num < minRoomNum) {
                minRoomNum = num;
                // id format: dorm__house__roomNumber__ffloor
                const generatedId = `${dormStr}__${houseStr}__${roomNumStr}__f${floorStr}`.toLowerCase().replace(/\s+/g, '_');
                minRoomId = generatedId;
            }
        }
    });

    console.log("Real smallest room num in Salisbury:", minRoomNum, "with ID:", minRoomId);
    
    // Find Shitbox Suite and remove it
    let shitboxIdx = entries.findIndex(e => e.customName && e.customName.toLowerCase() === 'shitbox suite');
    let shitboxEntry = null;
    if (shitboxIdx !== -1) {
        shitboxEntry = entries[shitboxIdx];
        shitboxEntry.roomId = minRoomId;
        shitboxEntry.tags = ["Tiny", "Cramped", "Dark"];
    } else {
        entries.push({
            entryId: Date.now().toString(),
            roomId: minRoomId,
            userEmail: "test@uchicago.edu",
            academicYear: "2024-2025",
            timestamp: new Date().toISOString(),
            tags: ["Tiny", "Cramped", "Dark"],
            scalars: {
                "my house has a good culture": 1,
                "my room gets a lot of outside noise": 5
            },
            customName: "Shitbox Suite"
        });
    }

    // Also remove any other entries for minRoomId so it doesn't have conflicting names
    const filteredEntries = entries.filter((e, idx) => {
        if (e.roomId === minRoomId && e !== shitboxEntry && (!e.customName || e.customName.toLowerCase() !== 'shitbox suite')) {
            return false;
        }
        return true;
    });

    // Make sure no other room comes before "Shitbox Suite" alphabetically in Salisbury
    // minRoomId tells us it's Salisbury
    filteredEntries.forEach(e => {
        if (e.roomId.includes('salisbury') && e.customName && e.customName.toLowerCase() !== 'shitbox suite') {
            if (e.customName.toLowerCase().localeCompare('shitbox suite') < 0) {
                console.log(`Renaming ${e.customName} to T-${e.customName} to keep Shitbox first`);
                e.customName = 'T-' + e.customName;
            }
        }
    });

    fs.writeFileSync(filename, JSON.stringify(filteredEntries, null, 2));
    console.log(`Updated ${filename} to put Shitbox Suite at ${minRoomId}`);
}

fixShitboxReal('data/fakeRoomEntries.json');
fixShitboxReal('data/roomEntries.json');
