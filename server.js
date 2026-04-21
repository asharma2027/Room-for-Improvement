require('dotenv').config();
const express = require('express');
const session = require('express-session');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const fs = require('fs-extra');
const path = require('path');
const parse = require('csv-parse').parse;
const stringify = require('csv-stringify').stringify;
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const {
  SESSION_SECRET,
  EMAIL_HOST,
  EMAIL_PORT,
  EMAIL_USER,
  EMAIL_PASS,
  APP_URL
} = process.env;

const PORT = process.env.PORT || 3000;
const app = express();

// Basic middlewares
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images/emblems', express.static(path.join(__dirname, 'data', 'House Emblems')));
app.use('/images/dorms', express.static(path.join(__dirname, 'data', 'dorm street views')));

// EJS setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session
app.use(session({
  secret: SESSION_SECRET || 'fallbackSecret',
  resave: false,
  saveUninitialized: false
}));

// Data paths
const USERS_JSON = path.join(__dirname, 'data', 'users.json');
const FEEDBACK_JSON = path.join(__dirname, 'data', 'feedback.json');

const USE_FAKE_DATA = true; // SET TO FALSE TO RESTORE REAL DATA
const ROOM_ENTRIES_JSON = USE_FAKE_DATA 
  ? path.join(__dirname, 'data', 'fakeRoomEntries.json') 
  : path.join(__dirname, 'data', 'roomEntries.json');

const ROOMS_CSV = path.join(__dirname, 'data', 'rooms.csv');

// ── DATA SOURCE TOGGLE ──────────────────────────────────────────────────────
// Set to true  → load rooms from per-building colored_rooms.csv files (REAL DATA)
// Set to false → load rooms from the old data/rooms.csv  (legacy placeholder data)
const USE_FLOORPLAN_CSV = true;

const FLOORPLAN_DIR = path.join(__dirname, 'data', 'floorplans');
// The six building sub-folders that have colored_rooms.csv files:
const FLOORPLAN_BUILDINGS = [
  'Burton-Judson',
  'I-House',
  'Max Palevsky',
  'Renee_Granville-Grossman',
  'Snell_Hitchcock',
  'Woodlawn'
];
// ────────────────────────────────────────────────────────────────────────────

// Ensure files exist
if (!fs.existsSync(USERS_JSON)) fs.writeJSONSync(USERS_JSON, []);
if (!fs.existsSync(FEEDBACK_JSON)) fs.writeJSONSync(FEEDBACK_JSON, []);
if (!fs.existsSync(ROOM_ENTRIES_JSON)) fs.writeJSONSync(ROOM_ENTRIES_JSON, []);

// Utility: read/write users
function readUsers() {
  try {
    return fs.readJSONSync(USERS_JSON);
  } catch {
    return [];
  }
}
function writeUsers(users) {
  fs.writeJSONSync(USERS_JSON, users, { spaces: 2 });
}

// Utility: read/write feedback
function readFeedback() {
  try {
    return fs.readJSONSync(FEEDBACK_JSON);
  } catch {
    return [];
  }
}
function writeFeedback(arr) {
  fs.writeJSONSync(FEEDBACK_JSON, arr, { spaces: 2 });
}

// Utility: read/write room entries
function readRoomEntries() {
  try {
    return fs.readJSONSync(ROOM_ENTRIES_JSON);
  } catch {
    return [];
  }
}
function writeRoomEntries(arr) {
  fs.writeJSONSync(ROOM_ENTRIES_JSON, arr, { spaces: 2 });
}

// ── NEW: load rooms from per-building colored_rooms.csv files ────────────────
// Each colored_rooms.csv has columns:
//   Room Number, Floor, Building Name, House Name, Room Type, Original Image
// We project these onto the shape the rest of the server expects:
//   { id, dorm, house, roomNumber, floor, roomType }
// 'id' is a stable deterministic slug so links/submissions stay consistent
// across server restarts.
function readRoomsFromFloorplans(callback) {
  const allRooms = [];
  let pending = FLOORPLAN_BUILDINGS.length;

  if (pending === 0) return callback(null, []);

  FLOORPLAN_BUILDINGS.forEach(building => {
    const csvPath = path.join(FLOORPLAN_DIR, building, 'colored_rooms.csv');
    fs.readFile(csvPath, 'utf8')
      .then(data => {
        parse(data, { columns: true }, (err, rows) => {
          if (!err && rows) {
            rows.forEach(row => {
              const dorm = (row['Building Name'] || '').trim();
              const house = (row['House Name'] || '').trim();
              const roomNumber = (row['Room Number'] || '').trim();
              const floor = (row['Floor'] || '').trim();
              const roomType = (row['Room Type'] || '').trim();

              if (!dorm || !house || !roomNumber) return; // skip malformed rows

              // Deterministic slug-based ID — stable across restarts.
              // Includes floor to guard against same room number on multiple floors.
              const id = `${dorm}__${house}__${roomNumber}__f${floor}`
                .toLowerCase()
                .replace(/\s+/g, '_');

              allRooms.push({ id, dorm, house, roomNumber, floor, roomType });
            });
          }
          pending--;
          if (pending === 0) callback(null, allRooms);
        });
      })
      .catch(() => {
        // Missing CSV for this building — skip gracefully
        pending--;
        if (pending === 0) callback(null, allRooms);
      });
  });
}
// ────────────────────────────────────────────────────────────────────────────

// Utility: read/write rooms from CSV
// Branches on USE_FLOORPLAN_CSV — set that flag to false to revert to legacy.
function readRooms(callback) {
  if (USE_FLOORPLAN_CSV) {
    return readRoomsFromFloorplans(callback);
  }
  // ── LEGACY PATH (old data/rooms.csv with placeholder data) ─────────────
  // fs.readFile(ROOMS_CSV, 'utf8')
  //   .then(data => {
  //     parse(data, { columns: true }, (err, rooms) => {
  //       if (err) return callback(err, null);
  //       callback(null, rooms);
  //     });
  //   })
  //   .catch(() => callback(null, []));
  // (kept for reference — unreachable while USE_FLOORPLAN_CSV === true)
  fs.readFile(ROOMS_CSV, 'utf8')
    .then(data => {
      parse(data, { columns: true }, (err, rooms) => {
        if (err) return callback(err, null);
        callback(null, rooms);
      });
    })
    .catch(() => callback(null, []));
}
function writeRooms(rooms, callback) {
  const columns = ['id', 'dorm', 'house', 'roomNumber'];
  stringify(rooms, { header: true, columns }, (err, output) => {
    if (err) return callback(err);
    fs.writeFile(ROOMS_CSV, output, 'utf8')
      .then(() => callback(null))
      .catch(callback);
  });
}

// Passport config
passport.serializeUser((user, done) => {
  done(null, user.email);
});
passport.deserializeUser((email, done) => {
  const all = readUsers();
  const found = all.find(u => u.email === email);
  done(null, found || false);
});
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, (email, password, done) => {
  const all = readUsers();
  const user = all.find(u => u.email === email.toLowerCase());
  if (!user) return done(null, false, { message: 'No such user.' });
  if (!user.verified) return done(null, false, { message: 'Not verified.' });

  bcrypt.compare(password, user.hashedPassword, (err, isMatch) => {
    if (err) return done(err);
    if (!isMatch) return done(null, false, { message: 'Incorrect password' });
    return done(null, user);
  });
}));
app.use(passport.initialize());
app.use(passport.session());

// Nodemailer for email verification
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  secure: false,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});
async function sendVerificationEmail(toEmail, token) {
  const link = `${APP_URL}/verify/${token}`;
  const mailOptions = {
    from: `"Room for Improvement" <${EMAIL_USER}>`,
    to: toEmail,
    subject: 'Verify your @uchicago.edu account',
    html: `
      <p>Thanks for registering! Please verify your email by clicking the link below:</p>
      <p><a href="${link}">${link}</a></p>
      <p>If you didn't sign up, ignore this email.</p>
    `
  };
  await transporter.sendMail(mailOptions);
}

// Auth check
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.redirect('/');
}

// Global Middleware to pass 'path' and 'user' to all views
app.use((req, res, next) => {
  res.locals.path = req.path;
  res.locals.user = req.user;
  next();
});

// -------------------- ROUTES --------------------

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

// Feedback
app.post('/feedback', (req, res) => {
  const allFeedback = readFeedback();
  const text = req.body.feedbackText?.trim() || '';
  const userEmail = req.user ? req.user.email : 'anonymous';

  if (text) {
    allFeedback.push({
      id: crypto.randomBytes(8).toString('hex'),
      user: userEmail,
      text,
      date: new Date().toISOString()
    });
    writeFeedback(allFeedback);
  }
  res.redirect('/');
});

// Register
app.get('/register', (req, res) => {
  res.render('register', { user: req.user });
});
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const lowerEmail = email.toLowerCase();

  if (!lowerEmail.endsWith('@uchicago.edu')) {
    return res.send('You must use an @uchicago.edu email.');
  }
  const users = readUsers();
  if (users.find(u => u.email === lowerEmail)) {
    return res.send('That email is already registered.');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const token = crypto.randomBytes(20).toString('hex');

  const newUser = {
    email: lowerEmail,
    hashedPassword,
    verified: false,
    verificationToken: token
  };
  users.push(newUser);
  writeUsers(users);

  try {
    await sendVerificationEmail(lowerEmail, token);
    res.send('Registration successful! Check your inbox for a verification link.');
  } catch (err) {
    console.error('Error sending email:', err);
    res.send('Error sending verification email. Please try again later.');
  }
});

// Verify
app.get('/verify/:token', (req, res) => {
  const token = req.params.token;
  const users = readUsers();
  const idx = users.findIndex(u => u.verificationToken === token);
  if (idx === -1) return res.send('Invalid or expired verification link.');

  users[idx].verified = true;
  users[idx].verificationToken = null;
  writeUsers(users);

  res.send('Your email has been verified! <a href="/">Return Home</a>');
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { user: req.user });
});
app.post('/login', passport.authenticate('local', {
  successRedirect: '/map',
  failureRedirect: '/login'
}));

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.redirect('/');
    });
  });
});

// -------------------- MAP --------------------

// House emblems: distinct color per house for demo
const HOUSE_COLORS = {
  // Burton-Judson
  'Chamberlin': '#c0392b', 'Coulter': '#8e44ad', 'Dodd Mead': '#2980b9',
  'Linn Mathews': '#16a085', 'Salisbury': '#d35400', 'Vincent': '#27ae60',
  // Woodlawn
  'Baker': '#e74c3c', 'Casner': '#9b59b6', 'Chenn': '#3498db',
  'Eka': '#1abc9c', 'Fama': '#f39c12', 'Gallo': '#e67e22',
  'Han': '#2ecc71', 'Liew': '#e91e63', 'Markovitz': '#00bcd4',
  'Rustandy': '#ff5722', 'Yovovich': '#795548',
  // Snell-Hitchcock
  'Hitchcock': '#5c6bc0', 'Snell': '#26a69a',
  // I-House
  'Booth': '#ef5350', 'Breckinridge': '#ab47bc', 'Phoenix': '#42a5f5',
  'Shorey': '#66bb6a', 'Thompson': '#ffa726',
  // Max Palevsky
  'Alper': '#ec407a', 'Flint': '#7e57c2', 'Graham': '#26c6da',
  'Hoover': '#d4e157', 'May': '#ff7043', 'Rickert': '#8d6e63',
  'Wallace': '#78909c', 'Woodward': '#26a69a',
  // Renee GRC
  'Cathey': '#f44336', 'Crown': '#673ab7', 'Delgiorno': '#03a9f4',
  'DelGiorno': '#03a9f4', 'Halperin': '#4caf50', 'Kenwood': '#ff9800', 'Wendt': '#009688'
};

function getHouseColor(house) {
  return HOUSE_COLORS[house] || '#800000';
}

// Compute ranking scores for all houses in a dorm
function computeDormRankings(dormName, rooms, entries) {
  const houses = {};

  // Initialize from rooms
  rooms.filter(r => r.dorm === dormName).forEach(r => {
    if (!r.house) return;
    if (!houses[r.house]) {
      houses[r.house] = {
        name: r.house,
        color: getHouseColor(r.house),
        initials: r.house.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2),
        emblem: getHouseEmblem(r.house),
        culture: [], noise: [], sunlight: [], roomSize: [], tempControl: [],
        roomCount: 0
      };
    }
    houses[r.house].roomCount++;
  });

  // Aggregate from entries
  entries.forEach(e => {
    const room = rooms.find(r => r.id === e.roomId);
    if (!room || room.dorm !== dormName || !houses[room.house]) return;
    const h = houses[room.house];

    if (e.scalars) {
      const c = parseFloat(e.scalars['my house has a good culture']);
      const n = parseFloat(e.scalars['my room gets a lot of outside noise']);
      if (!isNaN(c)) h.culture.push(c);
      if (!isNaN(n)) h.noise.push(n);
    }
    if (e.tags && Array.isArray(e.tags)) {
      const tags = e.tags.map(t => t.toLowerCase());
      if (tags.some(t => t.includes('sunlight') || t.includes('sunny') || t.includes('bright'))) h.sunlight.push(1);
      else h.sunlight.push(0);
      if (tags.some(t => t.includes('big') || t.includes('large') || t.includes('spacious'))) h.roomSize.push(1);
      else if (tags.some(t => t.includes('small') || t.includes('tiny') || t.includes('cramped'))) h.roomSize.push(-1);
      else h.roomSize.push(0);
      if (tags.some(t => t.includes('ac') || t.includes('temperature') || t.includes('drafty') || t.includes('heating'))) h.tempControl.push(0);
      else h.tempControl.push(1);
    }
  });

  const avg = arr => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;

  return Object.values(houses).map(h => ({
    name: h.name,
    color: h.color,
    initials: h.initials,
    emblem: h.emblem,
    roomCount: h.roomCount,
    scores: {
      culture: avg(h.culture),
      quietness: h.noise.length ? (6 - avg(h.noise)) : null, // invert noise
      sunlight: avg(h.sunlight),
      roomSize: avg(h.roomSize),
      tempControl: avg(h.tempControl)
    }
  }));
}

// Emblems & Backgrounds Mapping
const houseEmblemsCache = {};
let emblemFiles = [];
try { emblemFiles = fs.readdirSync(path.join(__dirname, 'data', 'House Emblems')); } catch(e) {}

function getHouseEmblem(houseName) {
  if (!houseName) return null;
  if (houseEmblemsCache[houseName]) return houseEmblemsCache[houseName];
  
  const lowerName = houseName.toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const file of emblemFiles) {
    if (file === '.DS_Store') continue;
    const lowerFile = file.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (lowerFile.includes(lowerName)) {
      houseEmblemsCache[houseName] = `/images/emblems/${encodeURIComponent(file)}`;
      return houseEmblemsCache[houseName];
    }
  }
  return null;
}

const dormBackgroundsCache = {};
let dormFiles = [];
try { dormFiles = fs.readdirSync(path.join(__dirname, 'data', 'dorm street views')); } catch(e) {}

function getDormBackground(dormName) {
  if (!dormName) return null;
  if (dormBackgroundsCache[dormName]) return dormBackgroundsCache[dormName];

  const lowerName = dormName.toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const file of dormFiles) {
    if (file === '.DS_Store') continue;
    const lowerFile = file.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (lowerFile.includes(lowerName) || lowerName.includes(lowerFile.replace(/(jpg|jpeg|png|gif)$/, ''))) {
      dormBackgroundsCache[dormName] = `/images/dorms/${encodeURIComponent(file)}`;
      return dormBackgroundsCache[dormName];
    }
  }
  if (lowerName.includes('renee') || lowerName.includes('south') || lowerName.includes('burton')) dormBackgroundsCache[dormName] = `/images/dorms/South-Campus-Res-Hall---Main.png`;
  else if (lowerName.includes('max') || lowerName.includes('north')) dormBackgroundsCache[dormName] = `/images/dorms/campusnorth.jpg`;
  else if (dormFiles.length > 0) dormBackgroundsCache[dormName] = `/images/dorms/${encodeURIComponent(dormFiles.find(f => f !== '.DS_Store') || 'South-Campus-Res-Hall---Main.png')}`;
  
  return dormBackgroundsCache[dormName] || null;
}

// GET /map - campus map
app.get('/map', ensureAuthenticated, (req, res) => {
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error');
    const dormHousesMap = buildDormHousesMap(rooms);
    // Build list of all houses for search
    const allHouses = [];
    Object.entries(dormHousesMap).forEach(([dorm, houses]) => {
      houses.forEach(house => {
        allHouses.push({
          house, dorm, color: getHouseColor(house),
          initials: house.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2),
          emblem: getHouseEmblem(house)
        });
      });
    });
    res.render('map', { user: req.user, allHousesJson: JSON.stringify(allHouses) });
  });
});

// GET /api/houses - JSON for search autocomplete
app.get('/api/houses', ensureAuthenticated, (req, res) => {
  readRooms((err, rooms) => {
    if (err) return res.json([]);
    const seen = new Set();
    const houses = [];
    rooms.forEach(r => {
      const key = `${r.dorm}::${r.house}`;
      if (!seen.has(key) && r.house) {
        seen.add(key);
        houses.push({
          house: r.house, dorm: r.dorm, color: getHouseColor(r.house),
          initials: r.house.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2),
          emblem: getHouseEmblem(r.house)
        });
      }
    });
    res.json(houses);
  });
});

// GET /dorm/:dorm - house rankings for a dorm
app.get('/dorm/:dorm', ensureAuthenticated, (req, res) => {
  const dormName = req.params.dorm;
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error');
    const entries = readRoomEntries();
    const rankings = computeDormRankings(dormName, rooms, entries);
    if (rankings.length === 0) return res.status(404).send('Dorm not found or no rooms data.');
    res.render('dormRankings', { user: req.user, dormName, rankings, rankingsJson: JSON.stringify(rankings) });
  });
});

// GET /house/:dorm/:house - house room list page
app.get('/house/:dorm/:house', ensureAuthenticated, (req, res) => {
  const dormName = req.params.dorm;
  const houseName = req.params.house;
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error');
    const houseRooms = rooms.filter(r => r.dorm === dormName && r.house === houseName);
    if (houseRooms.length === 0) return res.status(404).send('House not found.');
    const allEntries = readRoomEntries();
    
    // Compute dorm rankings to get this house's placement
    const rankings = computeDormRankings(dormName, rooms, allEntries);
    let houseRanks = null;
    const houseRankObj = rankings.find(r => r.name === houseName);
    if (houseRankObj) {
      houseRanks = {};
      const categoryKeys = [
        { key: 'culture', ejsKey: 'culture', asc: false },
        { key: 'noise', ejsKey: 'quietness', asc: true },
        { key: 'sunlight', ejsKey: 'sunlight', asc: false },
        { key: 'roomSize', ejsKey: 'roomSize', asc: false },
        { key: 'tempControl', ejsKey: 'tempControl', asc: false }
      ];
      categoryKeys.forEach(cat => {
        const sorted = [...rankings].filter(r => r.scores[cat.key] !== null).sort((a,b) => {
          const va = a.scores[cat.key];
          const vb = b.scores[cat.key];
          return cat.asc ? va - vb : vb - va;
        });
        const rankIndex = sorted.findIndex(r => r.name === houseName);
        if (rankIndex !== -1) {
          houseRanks[cat.ejsKey] = rankIndex + 1;
        } else {
          houseRanks[cat.ejsKey] = null;
        }
      });
    }

    // Aggregated culture chips/notes and house descriptors across all submissions for this house.
    const cultureWords = [];        // For "Culture Vibes" word cloud
    const houseDescriptorWords = []; // For "House Descriptors" word cloud
    const allHouseEntries = allEntries.filter(e => {
      const room = rooms.find(r => r.id === e.roomId);
      return room && room.dorm === dormName && room.house === houseName;
    });
    allHouseEntries.forEach(e => {
      if (Array.isArray(e.cultureTags)) {
        e.cultureTags.forEach(c => { if (c) cultureWords.push(String(c)); });
      }
      if (e.scalars && e.scalars["culture note"]) {
        cultureWords.push(String(e.scalars["culture note"]));
      }
      if (e.scalars && e.scalars["house descriptor"]) {
        houseDescriptorWords.push(String(e.scalars["house descriptor"]));
      }
    });

    houseRooms.forEach(r => {
      r.tags = ''; r.houseCultureVal = ''; r.outsideNoiseVal = ''; r.customName = null;
      r.roomSizeVal = ''; r.naturalLightVal = ''; r.tempControlVal = '';
      const matching = allEntries.filter(e => e.roomId === r.id);
      if (matching.length > 0) {
        matching.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        const latest = matching[matching.length - 1];
        if (latest.tags && latest.tags.length > 0) r.tags = latest.tags.join(', ');
        if (latest.scalars) {
          r.houseCultureVal = latest.scalars['my house has a good culture'] || '';
          r.outsideNoiseVal = latest.scalars['my room gets a lot of outside noise'] || '';
        }
        if (latest.customName) r.customName = latest.customName;

        // Most recent v2 scalars (walk from newest backward to find first v2 entry for each).
        for (let i = matching.length - 1; i >= 0; i--) {
          const s = matching[i].scalars || {};
          if (s["form version"] === "v2") {
            if (!r.roomSizeVal && s["room size"])          r.roomSizeVal = s["room size"];
            if (!r.naturalLightVal && s["natural light"])  r.naturalLightVal = s["natural light"];
            if (!r.tempControlVal && s["temperature control"]) r.tempControlVal = s["temperature control"];
            if (r.roomSizeVal && r.naturalLightVal && r.tempControlVal) break;
          }
        }
      }
    });

    // Build distinct filter lists (floors + room types present in this house).
    const floorsSet = new Set();
    const roomTypesSet = new Set();
    houseRooms.forEach(r => {
      if (r.floor)    floorsSet.add(r.floor);
      if (r.roomType) roomTypesSet.add(r.roomType);
    });
    const floors    = Array.from(floorsSet).sort();
    const roomTypes = Array.from(roomTypesSet).sort();

    res.render('housePage', {
      user: req.user, dormName, houseName,
      houseColor: getHouseColor(houseName),
      houseInitials: houseName.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2),
      houseEmblem: getHouseEmblem(houseName),
      dormBackground: getDormBackground(dormName),
      rooms: houseRooms,
      houseRanks,
      cultureWords,
      houseDescriptorWords,
      floors,
      roomTypes
    });
  });
});

// GET /house/:dorm/:house/board - house community board
app.get('/house/:dorm/:house/board', ensureAuthenticated, (req, res) => {
  const dormName = req.params.dorm;
  const houseName = req.params.house;
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error');
    const houseRooms = rooms.filter(r => r.dorm === dormName && r.house === houseName);
    if (houseRooms.length === 0) return res.status(404).send('House not found.');
    res.render('houseBoard', {
      user: req.user, dormName, houseName,
      houseColor: getHouseColor(houseName),
      houseInitials: houseName.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2),
      houseEmblem: getHouseEmblem(houseName),
      dormBackground: getDormBackground(dormName)
    });
  });
});

// -------------------- ROOMS --------------------

// *** CHANGED *** HELPER FUNCTION TO BUILD A (DORM -> SET OF HOUSES) MAP
function buildDormHousesMap(rooms) {
  // returns { "Max Palevsky": ["HouseA","HouseB"], "Campus North": ["X","Y"] }
  const map = {};
  rooms.forEach(r => {
    if (!map[r.dorm]) {
      map[r.dorm] = new Set();
    }
    map[r.dorm].add(r.house);
  });
  // convert each set to array
  Object.keys(map).forEach(d => {
    map[d] = Array.from(map[d]);
  });
  return map;
}

// *** CHANGED *** HELPER FUNCTIONS FOR "TOP 3 HOUSES"
function computeTopHousesCulture(rooms, limit = 3) {
  const grouped = {};
  rooms.forEach(r => {
    if (!r.house) return;
    if (r.houseCultureVal) {
      const val = parseFloat(r.houseCultureVal);
      if (!isNaN(val)) {
        if (!grouped[r.house]) grouped[r.house] = [];
        grouped[r.house].push(val);
      }
    }
  });

  // compute average
  const results = [];
  for (const house in grouped) {
    const arr = grouped[house];
    const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
    results.push({ houseName: house, avg });
  }
  // sort descending (since higher is better for culture)
  results.sort((a, b) => b.avg - a.avg);
  return results.slice(0, limit);
}

function computeTopHousesNoise(rooms, limit = 3) {
  const grouped = {};
  rooms.forEach(r => {
    if (!r.house) return;
    if (r.outsideNoiseVal) {
      const val = parseFloat(r.outsideNoiseVal);
      if (!isNaN(val)) {
        if (!grouped[r.house]) grouped[r.house] = [];
        grouped[r.house].push(val);
      }
    }
  });

  const results = [];
  for (const house in grouped) {
    const arr = grouped[house];
    const avg = arr.reduce((a, b) => a + b, 0) / arr.length;
    results.push({ houseName: house, avg });
  }
  // sort ascending (since lower is better for noise)
  results.sort((a, b) => a.avg - b.avg);
  return results.slice(0, limit);
}

// Show list of rooms
app.get('/rooms', ensureAuthenticated, (req, res) => {
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error reading rooms CSV');

    let filtered = rooms;
    // Optional search param
    const q = req.query.q || '';
    if (q) {
      filtered = rooms.filter(r => {
        const haystack = [
          r.dorm || '',
          r.house || '',
          r.roomNumber || ''
        ].join(' ').toLowerCase();
        return haystack.includes(q.toLowerCase());
      });
    }

    // Load all room entries
    const allEntries = readRoomEntries();

    // For each room, find the LATEST submission
    filtered.forEach(r => {
      // default blank if no submission
      r.tags = '';
      r.houseCultureVal = '';
      r.outsideNoiseVal = '';
      r.customName = null;

      const matching = allEntries.filter(e => e.roomId === r.id);
      if (matching.length > 0) {
        matching.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        const latest = matching[matching.length - 1];

        if (latest.tags && latest.tags.length > 0) {
          r.tags = latest.tags.join(', ');
        }
        if (latest.scalars) {
          const hc = latest.scalars["my house has a good culture"];
          const noise = latest.scalars["my room gets a lot of outside noise"];
          r.houseCultureVal = hc ? hc : '';
          r.outsideNoiseVal = noise ? noise : '';
        }
        if (latest.customName) {
          r.customName = latest.customName;
        }
      }
    });

    // *** CHANGED *** BUILD THE dormHousesMap
    const dormHousesMap = buildDormHousesMap(rooms);

    // *** CHANGED *** DETERMINE IF USER SELECTED A DORM
    // If user is in client-side mode, we won't have a param. But let's assume no param for dorm.
    // If you do want a server param for dorm=someDorm, you can do it. We'll skip for now.

    // We'll compute "top 3 houses" across the "filtered" set if they used search,
    // or from the entire set if you want the unfiltered. 
    // The problem states "When on the all dorms page, top 3 across all dorms. 
    // If user selects a dorm, top 3 for that dorm." 
    // We'll interpret "all dorms page" as when user hasn't used the dorm filter or if "dorm-filter" is empty.
    // BUT we only have a client side approach. We'll do the aggregator on "rooms" or "filtered"? 
    // We'll do aggregator on "filtered" for consistent approach. 
    // That means if user typed something in search, it might reduce the set. That's your call. 
    // For the user story, let's do aggregator on the entire "rooms" or do aggregator on the "filtered"? 
    // We'll do aggregator on "filtered," so if user picks a dorm client-side, 
    // the aggregator changes. We'll keep it simpler to do aggregator on "filtered."

    const topHousesCulture = computeTopHousesCulture(filtered);
    const topHousesNoise = computeTopHousesNoise(filtered);

    res.render('rooms', {
      user: req.user,
      rooms: filtered,
      query: q,
      dormHousesMap,
      topHousesCulture,
      topHousesNoise,
      // Pre-serialize for client-side
      dormHousesMapJson: JSON.stringify(dormHousesMap || {}),
      allRoomsDataJson: JSON.stringify(filtered || [])
    });
  });
});

// Room details
app.get('/rooms/:id', ensureAuthenticated, (req, res) => {
  const roomId = req.params.id;
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error reading rooms CSV');
    const room = rooms.find(r => r.id === roomId);
    if (!room) return res.status(404).send('Room not found');

    // Gather all entries for this room
    const allEntries = readRoomEntries().filter(e => e.roomId === roomId);
    allEntries.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    // The latest entry if any
    const latestEntry = allEntries.length > 0 ? allEntries[allEntries.length - 1] : null;

    // Check if current user has already submitted for this academic year (except test account)
    const userEmail = req.user.email;
    let alreadySubmittedThisYear = null;

    if (userEmail !== 'test@uchicago.edu') {
      allEntries.forEach(en => {
        if (en.userEmail === userEmail && !alreadySubmittedThisYear) {
          alreadySubmittedThisYear = en.academicYear;
        }
      });
    }

    // We'll keep CSV-based notes in room.tags if it existed, or blank
    if (!room.tags) {
      room.tags = '';
    }

    res.render('roomDetails', {
      user: req.user,
      room,
      latestEntry,
      allEntries,
      alreadySubmittedThisYear
    });
  });
});

// Room review form (separate page)
app.get('/rooms/:id/review', ensureAuthenticated, (req, res) => {
  const roomId = req.params.id;
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error reading rooms CSV');
    const room = rooms.find(r => r.id === roomId);
    if (!room) return res.status(404).send('Room not found');

    if (!room.tags) room.tags = '';

    const allEntries = readRoomEntries().filter(e => e.roomId === roomId);
    const userEmail = req.user.email;
    let alreadySubmittedThisYear = null;

    if (userEmail !== 'test@uchicago.edu') {
      allEntries.forEach(en => {
        if (en.userEmail === userEmail && !alreadySubmittedThisYear) {
          alreadySubmittedThisYear = en.academicYear;
        }
      });
    }

    res.render('roomReview', {
      user: req.user,
      room,
      alreadySubmittedThisYear
    });
  });
});

// Submit curated tags + scalars
app.post('/rooms/:id/submit', ensureAuthenticated, (req, res) => {
  const roomId = req.params.id;
  const {
    academicYear, tags, customName, form_version,
    scalar_house_culture, scalar_outside_noise,
    scalar_room_size, scalar_natural_light, scalar_temp_control,
    culture_note, freetext_note, culture_tags,
    house_descriptor
  } = req.body;

  let tagsArray = [];
  if (Array.isArray(tags)) {
    tagsArray = tags;
  } else if (typeof tags === 'string') {
    tagsArray = [tags];
  }

  let cultureTagsArray = [];
  if (Array.isArray(culture_tags)) {
    cultureTagsArray = culture_tags;
  } else if (typeof culture_tags === 'string') {
    cultureTagsArray = [culture_tags];
  }

  const houseCultureVal = parseInt(scalar_house_culture, 10);
  const outsideNoiseVal = parseInt(scalar_outside_noise, 10);

  const allEntries = readRoomEntries();
  const userEmail = req.user.email;

  // check if user has an existing submission for same year (except test account)
  const existing = allEntries.find(e =>
    e.roomId === roomId &&
    e.userEmail === userEmail &&
    e.academicYear === academicYear
  );
  if (existing && userEmail !== 'test@uchicago.edu') {
    return res.send('You already submitted data for this room in that academic year.');
  }

  // Build scalars — always preserve the two keys used by computeDormRankings()
  const scalars = {
    "my house has a good culture": houseCultureVal,
    "my room gets a lot of outside noise": outsideNoiseVal
  };

  if (form_version === 'v2') {
    scalars["room size"]            = parseInt(scalar_room_size, 10);
    scalars["natural light"]        = parseInt(scalar_natural_light, 10);
    scalars["temperature control"]  = parseInt(scalar_temp_control, 10);
    if (culture_note && culture_note.trim()) {
      scalars["culture note"] = culture_note.trim().slice(0, 100);
    }
    if (freetext_note && freetext_note.trim()) {
      scalars["freetext note"] = freetext_note.trim().slice(0, 280);
    }
    if (house_descriptor && house_descriptor.trim()) {
      scalars["house descriptor"] = house_descriptor.trim().slice(0, 120);
    }
    scalars["form version"] = "v2";
  }

  const newEntry = {
    entryId: crypto.randomBytes(8).toString('hex'),
    roomId,
    userEmail,
    academicYear,
    timestamp: new Date().toISOString(),
    tags: tagsArray,
    scalars,
    customName: customName && customName.trim() ? customName.trim() : null
  };

  // Store culture descriptor chips separately (not mixed into physical tags)
  if (form_version === 'v2' && cultureTagsArray.length > 0) {
    newEntry.cultureTags = cultureTagsArray.slice(0, 3);
  }

  allEntries.push(newEntry);
  writeRoomEntries(allEntries);

  res.redirect(`/rooms/${roomId}?submitted=1`);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at ${APP_URL}`);
});
