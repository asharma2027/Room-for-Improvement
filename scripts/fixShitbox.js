const fs = require('fs');

function fixShitbox(filename) {
    if (!fs.existsSync(filename)) return;
    const entries = JSON.parse(fs.readFileSync(filename, 'utf8'));

    const roomsCsvData = fs.readFileSync('data/rooms.csv', 'utf8').split('\n');
    let minRoomNum = Infinity;
    let minRoomId = "";

    roomsCsvData.slice(1).forEach(row => {
        const parts = row.split(',');
        if (parts.length < 4) return;
        const dorm = parts[1].trim();
        const house = parts[2].trim();
        const roomNumStr = parts[3].trim();
        const roomId = parts[0].trim();
        
        if (dorm === 'Burton Judson' && house === 'Salisbury') {
            const num = parseInt(roomNumStr);
            if (!isNaN(num) && num < minRoomNum) {
                minRoomNum = num;
                minRoomId = roomId;
            }
        }
    });

    console.log("Smallest room num in Salisbury:", minRoomNum, "with ID:", minRoomId);
    
    // Find Shitbox Suite and remove it
    let shitboxIdx = entries.findIndex(e => e.customName && e.customName.toLowerCase() === 'shitbox suite');
    let shitboxEntry = null;
    if (shitboxIdx !== -1) {
        shitboxEntry = entries[shitboxIdx];
        // Change its roomId
        shitboxEntry.roomId = minRoomId;
    } else {
        entries.push({
            entryId: Date.now().toString(),
            roomId: minRoomId,
            userEmail: "test@uchicago.edu",
            academicYear: "2024-2025",
            timestamp: new Date().toISOString(),
            tags: ["Smelly", "Dark", "Small"],
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


    fs.writeFileSync(filename, JSON.stringify(filteredEntries, null, 2));
    console.log(`Updated ${filename} to put Shitbox Suite at ${minRoomId}`);
}

fixShitbox('data/fakeRoomEntries.json');
fixShitbox('data/roomEntries.json');
