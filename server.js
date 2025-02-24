/***************************************************************
 * server.js
 * 
 * Implements:
 *  - Email/password login with verification (@uchicago.edu only)
 *  - Feedback form (top of homepage) stored in feedback.json
 *  - Rooms from rooms.csv
 *  - Per-room curated tags & scalar data, stored in roomEntries.json
 *  - Only one submission per user per room per academic year
 *  - Latest data shown by default; a historical table on the same page
 ***************************************************************/
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

// Ensure data files exist
if (!fs.existsSync(USERS_JSON)) fs.writeJSONSync(USERS_JSON, []);
if (!fs.existsSync(FEEDBACK_JSON)) fs.writeJSONSync(FEEDBACK_JSON, []);
if (!fs.existsSync(ROOM_ENTRIES_JSON)) fs.writeJSONSync(ROOM_ENTRIES_JSON, []);

// Helper to read/write users
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

// Helper to read/write feedback
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

// Helper to read/write room entries
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

// CSV read for rooms
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

// Write rooms if needed
function writeRooms(rooms, callback) {
  const columns = ['id', 'dormName', 'roomNumber', 'tags'];
  stringify(rooms, { header: true, columns }, (err, output) => {
    if (err) return callback(err);
    fs.writeFile(ROOMS_CSV, output, 'utf8').then(() => callback(null)).catch(callback);
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

// Nodemailer
const transporter = nodemailer.createTransport({
  host: EMAIL_HOST,
  port: EMAIL_PORT,
  secure: false,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// Send verification email
async function sendVerificationEmail(toEmail, token) {
  const link = `${APP_URL}/verify/${token}`;
  const mailOptions = {
    from: `"Room Improvement" <${EMAIL_USER}>`,
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

// Auth middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.redirect('/');
}

// --------------------- Routes ---------------------

// Home
app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

// Feedback POST
app.post('/feedback', (req, res) => {
  const feedbackArr = readFeedback();
  const text = req.body.feedbackText?.trim() || '';

  // Optional: require user login. For now, we allow anyone (but we store user if logged in).
  const userEmail = req.user ? req.user.email : 'anonymous';

  if (text) {
    feedbackArr.push({
      id: crypto.randomBytes(8).toString('hex'),
      user: userEmail,
      text,
      date: new Date().toISOString()
    });
    writeFeedback(feedbackArr);
  }
  res.redirect('/');
});

// Register GET
app.get('/register', (req, res) => {
  res.render('register', { user: req.user });
});

// Register POST
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

// Login GET
app.get('/login', (req, res) => {
  res.render('login', { user: req.user });
});

// Login POST
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

// Rooms listing
app.get('/rooms', ensureAuthenticated, (req, res) => {
  readRooms((err, rooms) => {
    if (err) return res.status(500).send('Error reading rooms CSV');
    const q = req.query.q || '';
    let filtered = rooms;
    if (q) {
      filtered = rooms.filter(r => {
        const allText = [r.dormName, r.roomNumber, r.tags].join(' ').toLowerCase();
        return allText.includes(q.toLowerCase());
      });
    }
    res.render('rooms', {
      user: req.user,
      rooms: filtered,
      query: q
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
    const allEntries = readRoomEntries().filter(e => e.roomId === roomId).sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));

    // The latest entry if any
    const latestEntry = allEntries.length > 0 ? allEntries[allEntries.length - 1] : null;

    // Check if current user has submitted this year
    // We'll parse academicYear from their previous entries
    // For example: if they have an entry with userEmail = user & academicYear = something, we disallow
    const userEmail = req.user.email;
    const currentYearEntries = allEntries.filter(e => e.userEmail === userEmail);
    // The form doesn't strictly define how you compare academicYear strings, but let's do a direct check
    // If the user tries to submit the same year again, we block it
    let alreadySubmittedThisYear = null; // store the year if they did
    currentYearEntries.forEach(en => {
      // They have an entry for that year => block
      if (!alreadySubmittedThisYear) {
        alreadySubmittedThisYear = en.academicYear; 
      }
    });

    res.render('roomDetails', {
      user: req.user,
      room,
      latestEntry,
      allEntries,
      alreadySubmittedThisYear
    });
  });
});

// POST: user submits curated tags + scalar data
app.post('/rooms/:id/submit', ensureAuthenticated, (req, res) => {
  const roomId = req.params.id;
  const { academicYear, tags, scalar_house_culture, scalar_outside_noise } = req.body;

  // Convert tags to an array
  let tagsArray = [];
  if (Array.isArray(tags)) {
    tagsArray = tags; // multiple checkboxes
  } else if (typeof tags === 'string') {
    tagsArray = [tags]; // single selection
  }

  // For safety, parse the scalars into numbers
  const houseCultureVal = parseInt(scalar_house_culture, 10);
  const outsideNoiseVal = parseInt(scalar_outside_noise, 10);

  // Read all room entries
  const entries = readRoomEntries();

  // Check if the user has already submitted for that academicYear
  const userEmail = req.user.email;
  const existing = entries.find(e => e.roomId === roomId && e.userEmail === userEmail && e.academicYear === academicYear);
  if (existing) {
    return res.send('You have already submitted for this room in the same academic year.');
  }

  // Create a new submission
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
  entries.push(newEntry);
  writeRoomEntries(entries);

  res.redirect(`/rooms/${roomId}`);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at ${APP_URL || 'http://localhost:' + PORT}`);
});
