/**
 * generateFakeData.js
 * -------------------
 * 1. Reads ALL rooms from the floorplan colored_rooms.csv files.
 * 2. Reads fakeRoomEntries.json.
 * 3. Removes any entry whose tags array is NOT a subset of the canonical v2 physical
 *    tags list, OR whose scalars don't include "form version": "v2".
 * 4. Also removes those same entries from the submission history (all entries for that
 *    room, because the data shape is wrong entirely for those fakes).
 * 5. Generates brand-new v2 submissions for approximately 80% of all rooms
 *    (skipping rooms that already have a valid v2 entry).
 * 6. Writes the result back to fakeRoomEntries.json.
 *
 * Run with:  node scripts/generateFakeData.js
 */

const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');
const crypto = require('crypto');

// ── Paths ────────────────────────────────────────────────────────────────────
const ROOT = path.join(__dirname, '..');
const FLOORPLAN_DIR = path.join(ROOT, 'data', 'floorplans');
const FAKE_ENTRIES_PATH = path.join(ROOT, 'data', 'fakeRoomEntries.json');

const FLOORPLAN_BUILDINGS = [
  'Burton-Judson',
  'I-House',
  'Max Palevsky',
  'Renee_Granville-Grossman',
  'Snell_Hitchcock',
  'Woodlawn'
];

// ── Canonical v2 physical tags (EXACTLY as used in the form/dropdown) ────────
const CANONICAL_TAGS = new Set([
  'particularly high ceiling',
  'particularly low ceiling',
  'extra storage / closet space',
  'limited storage / closet space',
  'unusually shaped room',
  'good furniture layout flexibility',
  'particularly big windows',
  'particularly small windows',
  'tends to receive good sunlight when sunny',
  'doesnt tend to receive good sunlight when sunny',
  'drafty windows',
  'notable hallway noise',
  'notable noise from adjacent rooms',
  'notable noise from above or below',
  'notably quiet despite building activity',
  'issues with ac/heating temperature control',
  'room tends to get very hot',
  'room tends to get very cold',
  'good natural ventilation',
  'poor natural ventilation',
  'significant radiator noise'
]);

// ── Canonical v2 culture tags ─────────────────────────────────────────────────
const CULTURE_TAGS = [
  'Welcoming / inclusive',
  'Tight-knit community',
  'Quiet / studious',
  'Lively / social',
  'Party-oriented',
  'Friendly but independent',
  'Cliquey / exclusive',
  'Competitive / high-pressure',
  'Disconnected / isolated',
  'Diverse mix of people',
  'Active house programming',
  'Floor rarely interacts'
];

// ── Realistic custom room names (student-style) ──────────────────────────────
const CUSTOM_NAMES = [
  // Cozy/warm vibes
  'The Cozy Corner', 'Sunshine Spot', 'The Nest', 'The Cave', 'The Burrow',
  // Grandiose/ironic
  'The Palace', 'Royal Suite', 'Presidential Suite', 'The Penthouse',
  // Functional/descriptive
  'Corner Room', 'The Study', 'The Library', 'Quiet Corner',
  // Fun/quirky
  'The Batcave', 'The Fortress', 'Hogwarts Annex', 'The Dungeon',
  'The Treehouse', 'The Hobbit Hole', 'The Shire', 'Narnia',
  // Minimalist
  'Room 101', 'The Box', 'Shoebox HQ', 'Postage Stamp',
  // Nature-themed
  'The Garden', 'Sunflower Suite', 'The Greenhouse', 'Rainforest Corner',
  // Campus-specific
  'Reg Adjacent', 'Library View', 'Courtyard Corner',
  'The Quad Side', 'Wind Tunnel West',
  // Wordplay
  'The Thinking Pod', 'Solitude Station', 'Deep Work Den',
  'Sleep Deprivation HQ', 'Caffeine Corner',
  // Architectural
  'The Tower Room', 'Bay Window Suite', 'High Ceilings HQ',
  'The Annex', 'Corner Office',
  // Temperature-themed
  'The Sauna', 'Arctic Suite', 'The Igloo', 'Tropical Room',
  // Light-themed
  'The Sunroom', 'The Skylight Suite', 'Golden Hour HQ', 'The Dimly Lit Den',
  // Noise-themed
  'The Quiet Sanctuary', 'Sound Studio East', 'Bass Drop Room',
  // Ironic/honest
  'Not As Bad As It Looks', 'Actually Pretty Good',
  'Surprisingly Spacious', 'Deceivingly Cozy'
];

// ── Culture note snippets (short, realistic) ──────────────────────────────────
const CULTURE_NOTES = [
  'super welcoming', 'pretty chill', 'everyone minds their own business',
  'lots of events', 'tight-knit floor', 'kind of cliquey at first',
  'study culture heavy', 'very social', 'quiet after 10pm',
  'RA is really active', 'big on house dinners', 'pretty isolated',
  'everyone keeps doors open', 'floor chat is dead', 'competitive but friendly',
  'great study groups', 'loud on weekends', 'super diverse',
  'feels like family', 'barely see neighbors'
];

// ── Freetext room notes (realistic student voice) ────────────────────────────
const FREETEXT_NOTES = [
  'The radiator is incredibly loud in winter — bring earplugs.',
  'Great room honestly. Bigger than it looks from outside.',
  'Hallway can get noisy on weekends but mostly fine.',
  'Natural light is amazing in the afternoon. Best part of the room.',
  'AC barely works in summer. Fan is essential.',
  'Corner room so you get noise from two hallways. Annoying.',
  'Really quiet, which is perfect for studying.',
  'The view of the courtyard makes it worth it.',
  'Small but manageable. You get used to it.',
  'Drafty windows in winter. Keep extra blankets.',
  'Best room on the floor, pretty much agreed.',
  'The ceiling is unusually high which makes it feel bigger.',
  'Closet space is terrible. Bring vacuum bags.',
  'Gets really warm in spring. Open windows help.',
  'Surprisingly quiet for being near the stairwell.',
  'The window faces west so evenings are bright and warm.',
  'Room is oddly shaped but you can make it work.',
  'Heating is inconsistent — some days too hot, some too cold.',
  'Really enjoyed living here. Would pick it again.',
  'Nothing special but nothing to complain about either.',
  'The floor above is loud. Could hear everything.',
  'Good ventilation — never felt stuffy.',
  'Beds are positioned awkwardly but furniture is moveable.',
  'The radiator noise took a week to get used to, then you forget it.',
  null // allow no note
];

// ── House descriptor snippets ────────────────────────────────────────────────
const HOUSE_DESCRIPTORS = [
  'cozy and social', 'quiet and studious', 'lively, lots of events',
  'tight-knit community', 'diverse and welcoming', 'academic-focused',
  'party-friendly', 'independent but friendly', 'bit cliquey at first',
  'RA-driven programming', 'chill, low-key vibes', 'very inclusive',
  'competitive energy', 'collaborative culture', 'strong house pride',
  null // allow no descriptor
];

// ── Utility ───────────────────────────────────────────────────────────────────
function rand(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pickN(arr, n) {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}

function isTagsValid(tagsArr) {
  if (!Array.isArray(tagsArr)) return false;
  return tagsArr.every(t => CANONICAL_TAGS.has(String(t)));
}

function isV2Entry(entry) {
  return (
    entry.scalars &&
    entry.scalars['form version'] === 'v2' &&
    typeof entry.scalars['room size'] === 'number' &&
    typeof entry.scalars['natural light'] === 'number' &&
    typeof entry.scalars['temperature control'] === 'number' &&
    typeof entry.scalars['my house has a good culture'] === 'number' &&
    typeof entry.scalars['my room gets a lot of outside noise'] === 'number' &&
    Array.isArray(entry.tags) &&
    isTagsValid(entry.tags) &&
    Array.isArray(entry.cultureTags) &&
    entry.cultureTags.every(ct => CULTURE_TAGS.includes(ct))
  );
}

// ── Load all rooms from floorplan CSVs ───────────────────────────────────────
function loadAllRooms() {
  const allRooms = [];
  for (const building of FLOORPLAN_BUILDINGS) {
    const csvPath = path.join(FLOORPLAN_DIR, building, 'colored_rooms.csv');
    if (!fs.existsSync(csvPath)) {
      console.warn(`  [WARN] Missing CSV: ${csvPath}`);
      continue;
    }
    const data = fs.readFileSync(csvPath, 'utf8');
    const rows = parse(data, { columns: true });
    for (const row of rows) {
      const dorm = (row['Building Name'] || '').trim();
      const house = (row['House Name'] || '').trim();
      const roomNumber = (row['Room Number'] || '').trim();
      const floor = (row['Floor'] || '').trim();
      const roomType = (row['Room Type'] || '').trim();
      if (!dorm || !house || !roomNumber) continue;
      const id = `${dorm}__${house}__${roomNumber}__f${floor}`
        .toLowerCase()
        .replace(/\s+/g, '_');
      allRooms.push({ id, dorm, house, roomNumber, floor, roomType });
    }
  }
  return allRooms;
}

// ── Generate a single v2 entry ───────────────────────────────────────────────
function generateV2Entry(room) {
  const studentN = randInt(1, 999);
  const userEmail = `student${studentN}@uchicago.edu`;

  // Random date within the 2024-2025 academic year (Oct 2024 – Apr 2025)
  const startMs = new Date('2024-10-01T00:00:00Z').getTime();
  const endMs   = new Date('2025-04-20T23:59:59Z').getTime();
  const timestamp = new Date(startMs + Math.random() * (endMs - startMs)).toISOString();

  // Physical tags: pick 0–4 random canonical tags
  const tagCount = randInt(0, 4);
  const tags = pickN(Array.from(CANONICAL_TAGS), tagCount);

  // Scalars — all 1–5 integers
  const scalars = {
    'my house has a good culture':          randInt(1, 5),
    'my room gets a lot of outside noise':  randInt(1, 5),
    'room size':                            randInt(1, 5),
    'natural light':                        randInt(1, 5),
    'temperature control':                  randInt(1, 5),
    'form version':                         'v2'
  };

  // Optional culture note (70% chance)
  if (Math.random() < 0.7) {
    scalars['culture note'] = rand(CULTURE_NOTES);
  }

  // Optional freetext note (55% chance)
  const note = rand(FREETEXT_NOTES);
  if (note && Math.random() < 0.55) {
    scalars['freetext note'] = note;
  }

  // Optional house descriptor (40% chance)
  const descriptor = rand(HOUSE_DESCRIPTORS);
  if (descriptor && Math.random() < 0.4) {
    scalars['house descriptor'] = descriptor;
  }

  // Culture tags: pick 1–3 random culture tags
  const ctCount = randInt(1, 3);
  const cultureTags = pickN(CULTURE_TAGS, ctCount);

  // Custom name: 60% chance of having one
  const customName = Math.random() < 0.6 ? rand(CUSTOM_NAMES) : null;

  return {
    entryId:      crypto.randomBytes(8).toString('hex'),
    roomId:       room.id,
    userEmail,
    academicYear: '2024-2025',
    timestamp,
    tags,
    scalars,
    cultureTags,
    customName
  };
}

// ── Main ─────────────────────────────────────────────────────────────────────
console.log('Loading rooms from floorplan CSVs…');
const allRooms = loadAllRooms();
console.log(`  → ${allRooms.length} rooms loaded`);

console.log('Reading fakeRoomEntries.json…');
let entries = [];
try {
  entries = JSON.parse(fs.readFileSync(FAKE_ENTRIES_PATH, 'utf8'));
  console.log(`  → ${entries.length} existing entries`);
} catch (e) {
  console.warn('  [WARN] Could not read fakeRoomEntries.json — starting fresh');
  entries = [];
}

// Step 1: Remove all entries that don't conform to v2 schema.
// We must also remove ALL entries for a room if ANY entry for that room is
// non-conforming (the user said "delete the submissions with the wrong data
// types from all submission history").
const nonConformingRoomIds = new Set();
for (const entry of entries) {
  if (!isV2Entry(entry)) {
    nonConformingRoomIds.add(entry.roomId);
  }
}
console.log(`\nNon-conforming room IDs (all their entries will be removed): ${nonConformingRoomIds.size}`);

const cleanedEntries = entries.filter(e => !nonConformingRoomIds.has(e.roomId));
console.log(`  → Kept ${cleanedEntries.length} conforming entries (removed ${entries.length - cleanedEntries.length})`);

// Step 2: Which rooms already have at least one valid v2 entry?
const roomsWithValidEntry = new Set(cleanedEntries.map(e => e.roomId));
const roomsNeedingEntry = allRooms.filter(r => !roomsWithValidEntry.has(r.id));
console.log(`\nRooms without a valid v2 entry: ${roomsNeedingEntry.length}`);

// Step 3: Fill 80% of rooms that need one.
// We also count already-covered rooms towards the 80% target.
const targetCoverage = Math.round(allRooms.length * 0.8);
const alreadyCovered = roomsWithValidEntry.size;
const needed = Math.max(0, targetCoverage - alreadyCovered);
console.log(`Target coverage: ${targetCoverage} rooms (80% of ${allRooms.length})`);
console.log(`Already covered: ${alreadyCovered}`);
console.log(`Need to generate: ${needed} new entries`);

// Shuffle roomsNeedingEntry and pick `needed`
const shuffled = [...roomsNeedingEntry].sort(() => Math.random() - 0.5);
const toFill = shuffled.slice(0, needed);

const newEntries = toFill.map(room => generateV2Entry(room));
console.log(`\nGenerated ${newEntries.length} new v2 entries`);

const finalEntries = [...cleanedEntries, ...newEntries];
console.log(`Total entries to write: ${finalEntries.length}`);

fs.writeFileSync(FAKE_ENTRIES_PATH, JSON.stringify(finalEntries, null, 2));
console.log(`\n✅  Done — wrote ${finalEntries.length} entries to fakeRoomEntries.json`);

// Summary
const coveredRooms = new Set(finalEntries.map(e => e.roomId));
console.log(`Final room coverage: ${coveredRooms.size} / ${allRooms.length} rooms (${((coveredRooms.size / allRooms.length) * 100).toFixed(1)}%)`);
