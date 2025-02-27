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
const ROOM_ENTRIES_JSON = path.join(__dirname, 'data', 'roomEntries.json');
const ROOMS_CSV = path.join(__dirname, 'data', 'rooms.csv');

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

// Utility: read/write rooms from CSV
function readRooms(callback) {
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
  const columns = ['id','dorm','house','roomNumber'];
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
  successRedirect: '/rooms',
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
    const avg = arr.reduce((a,b) => a+b, 0) / arr.length;
    results.push({ houseName: house, avg });
  }
  // sort descending (since higher is better for culture)
  results.sort((a,b) => b.avg - a.avg);
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
    const avg = arr.reduce((a,b) => a+b, 0) / arr.length;
    results.push({ houseName: house, avg });
  }
  // sort ascending (since lower is better for noise)
  results.sort((a,b) => a.avg - b.avg);
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

      const matching = allEntries.filter(e => e.roomId === r.id);
      if (matching.length > 0) {
        matching.sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
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
      dormHousesMap,        // *** CHANGED ***
      topHousesCulture,     // *** CHANGED ***
      topHousesNoise        // *** CHANGED ***
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
    allEntries.sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));

    // The latest entry if any
    const latestEntry = allEntries.length > 0 ? allEntries[allEntries.length - 1] : null;

    // Check if current user has already submitted for this academic year
    const userEmail = req.user.email;
    let alreadySubmittedThisYear = null;

    allEntries.forEach(en => {
      if (en.userEmail === userEmail && !alreadySubmittedThisYear) {
        alreadySubmittedThisYear = en.academicYear;
      }
    });

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

// Submit curated tags + scalars
app.post('/rooms/:id/submit', ensureAuthenticated, (req, res) => {
  const roomId = req.params.id;
  const { academicYear, tags, scalar_house_culture, scalar_outside_noise } = req.body;
  
  let tagsArray = [];
  if (Array.isArray(tags)) {
    tagsArray = tags;
  } else if (typeof tags === 'string') {
    tagsArray = [tags];
  }

  const houseCultureVal = parseInt(scalar_house_culture, 10);
  const outsideNoiseVal = parseInt(scalar_outside_noise, 10);

  const allEntries = readRoomEntries();
  const userEmail = req.user.email;

  // check if user has an existing submission for same year
  const existing = allEntries.find(e => 
    e.roomId === roomId && 
    e.userEmail === userEmail && 
    e.academicYear === academicYear
  );
  if (existing) {
    return res.send('You already submitted data for this room in that academic year.');
  }

  const newEntry = {
    entryId: crypto.randomBytes(8).toString('hex'),
    roomId,
    userEmail,
    academicYear,
    timestamp: new Date().toISOString(),
    tags: tagsArray,
    scalars: {
      "my house has a good culture": houseCultureVal,
      "my room gets a lot of outside noise": outsideNoiseVal
    }
  };
  allEntries.push(newEntry);
  writeRoomEntries(allEntries);

  res.redirect(`/rooms/${roomId}`);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at ${APP_URL || 'http://localhost:' + PORT}`);
});
