// One-shot: scan review data files for contradictory tag pairs and remove BOTH
// tags from any entry that contains a conflict. Writes the files back in place
// and prints a summary to stdout.
//
// Pairs (case-insensitive substring match on tag text):
//   1. "particularly low ceiling"   ↔ "particularly high ceiling"
//   2. "particularly small windows" ↔ "particularly big windows"
//   3. "poor sunlight"              ↔ "good sunlight"
//   4. "poor ventilation"           ↔ "good ventilation"

const fs = require('fs');
const path = require('path');

const FILES = [
  path.join(__dirname, '..', 'data', 'roomEntries.json'),
  path.join(__dirname, '..', 'data', 'fakeRoomEntries.json'),
];

const PAIRS = [
  ['particularly low ceiling',   'particularly high ceiling'],
  ['particularly small windows', 'particularly big windows'],
  ['poor sunlight',              'good sunlight'],
  ['poor ventilation',           'good ventilation'],
];

function norm(s) { return (s || '').toString().trim().toLowerCase(); }

function cleanEntry(entry) {
  if (!entry || !Array.isArray(entry.tags)) return { removed: [] };
  const removed = [];
  for (const [a, b] of PAIRS) {
    const hasA = entry.tags.some(t => norm(t).includes(a));
    const hasB = entry.tags.some(t => norm(t).includes(b));
    if (hasA && hasB) {
      const before = entry.tags.slice();
      entry.tags = entry.tags.filter(t => {
        const n = norm(t);
        return !(n.includes(a) || n.includes(b));
      });
      removed.push({
        pair: [a, b],
        dropped: before.filter(t => !entry.tags.includes(t)),
      });
    }
  }
  return { removed };
}

let grandTotal = 0;

for (const file of FILES) {
  if (!fs.existsSync(file)) {
    console.log(`skip (missing): ${file}`);
    continue;
  }
  const raw = fs.readFileSync(file, 'utf8');
  if (!raw.trim()) {
    console.log(`skip (empty): ${file}`);
    continue;
  }
  const data = JSON.parse(raw);
  if (!Array.isArray(data)) {
    console.log(`skip (not an array): ${file}`);
    continue;
  }

  let changed = 0;
  const notes = [];
  for (const entry of data) {
    const { removed } = cleanEntry(entry);
    if (removed.length > 0) {
      changed++;
      notes.push({ entryId: entry.entryId || entry.id || '(no-id)', roomId: entry.roomId, removed });
    }
  }

  if (changed > 0) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }
  grandTotal += changed;

  console.log(`\n=== ${path.basename(file)} ===`);
  console.log(`  entries scanned: ${data.length}`);
  console.log(`  entries fixed:   ${changed}`);
  for (const n of notes) {
    console.log(`  - ${n.entryId} (room ${n.roomId})`);
    for (const r of n.removed) {
      console.log(`      pair [${r.pair.join(' ↔ ')}] → dropped: ${JSON.stringify(r.dropped)}`);
    }
  }
}

console.log(`\nTOTAL entries fixed across all files: ${grandTotal}`);
