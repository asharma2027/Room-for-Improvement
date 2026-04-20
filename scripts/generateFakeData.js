const fs = require('fs-extra');
const path = require('path');
const parse = require('csv-parse').parse;
const crypto = require('crypto');

const FLOORPLAN_DIR = path.join(__dirname, '..', 'data', 'floorplans');
const FLOORPLAN_BUILDINGS = [
  'Burton-Judson', 'I-House', 'Max Palevsky',
  'Renee_Granville-Grossman', 'Snell_Hitchcock', 'Woodlawn'
];

function generateFakeData(rooms) {
  const entries = [];
  const fakeTags = ['Sunny', 'Spacious', 'Quiet', 'AC works well', 'Great view', 'Drafty', 'Close to stairs', 'Good culture', 'Tiny', 'Loud outside', 'Social', 'Big windows'];
  const fakeNames = ["The Suite Life", "Corner Pocket", "Sunshine Room", "Study Haven", "The Batcave", "Chill Zone", "Party Central", "The Oasis", "Cozy Corner", "Panoramic Suite"];

  rooms.forEach(room => {
    // ~70% chance to have an entry so the site feels very alive
    if (Math.random() > 0.3) {
      // Pick 2-5 random tags
      const numTags = Math.floor(Math.random() * 4) + 2;
      const roomTags = [];
      for(let i = 0; i < numTags; i++) {
        const tag = fakeTags[Math.floor(Math.random() * fakeTags.length)];
        if (!roomTags.includes(tag)) roomTags.push(tag);
      }
      
      const hasCustomName = Math.random() > 0.8;
      
      // Cultural bias so numbers vary
      let cultureBias = 3;
      let noiseBias = 3;
      if (room.house) {
        cultureBias = (room.house.length % 3) + 2; // 2 to 4
        noiseBias = (room.house.charCodeAt(0) % 3) + 2; // 2 to 4
      }

      entries.push({
        entryId: crypto.randomBytes(8).toString('hex'),
        roomId: room.id,
        userEmail: `student${Math.floor(Math.random()*1000)}@uchicago.edu`,
        academicYear: "2024-2025",
        timestamp: new Date(Date.now() - Math.random() * 10000000000).toISOString(),
        tags: roomTags,
        scalars: {
          "my house has a good culture": Math.min(5, Math.max(1, cultureBias + Math.floor(Math.random() * 3) - 1)),
          "my room gets a lot of outside noise": Math.min(5, Math.max(1, noiseBias + Math.floor(Math.random() * 3) - 1))
        },
        customName: hasCustomName ? fakeNames[Math.floor(Math.random() * fakeNames.length)] : null
      });
    }
  });

  fs.writeJSONSync(path.join(__dirname, '..', 'data', 'fakeRoomEntries.json'), entries, { spaces: 2 });
  console.log(`Generated ${entries.length} fake room entries into data/fakeRoomEntries.json.`);
}

const allRooms = [];
let pending = FLOORPLAN_BUILDINGS.length;

if (pending === 0) {
  generateFakeData([]);
} else {
  FLOORPLAN_BUILDINGS.forEach(building => {
    const csvPath = path.join(FLOORPLAN_DIR, building, 'colored_rooms.csv');
    if (fs.existsSync(csvPath)) {
      const data = fs.readFileSync(csvPath, 'utf8');
      parse(data, { columns: true }, (err, rows) => {
        if (!err && rows) {
          rows.forEach(row => {
            const dorm = (row['Building Name'] || '').trim();
            const house = (row['House Name'] || '').trim();
            const roomNumber = (row['Room Number'] || '').trim();
            const floor = (row['Floor'] || '').trim();
            const roomType = (row['Room Type'] || '').trim();

            if (!dorm || !house || !roomNumber) return;
            const id = `${dorm}__${house}__${roomNumber}__f${floor}`.toLowerCase().replace(/\s+/g, '_');
            allRooms.push({ id, dorm, house, roomNumber, floor, roomType });
          });
        }
        pending--;
        if (pending === 0) generateFakeData(allRooms);
      });
    } else {
      pending--;
      if (pending === 0) generateFakeData(allRooms);
    }
  });
}
