# Room for Improvement — Instructor Setup Guide

This is a full-stack Node.js web app. Setup takes about **2 minutes**.

---

## The Only Prerequisite

**Node.js** (v18 or later) — download at https://nodejs.org if you don't have it.

Check if you already have it:
```
node -v
```

---

## Running the Site

### Mac / Linux
Double-click `setup.sh`, or run in terminal from the project root:
```
bash instructor_setup/setup.sh
```

### Windows
Double-click `setup.bat`.

---

That's it. The script will:
1. Install all dependencies automatically
2. Start the server
3. Open **http://localhost:3000** in your browser

---

## Login Credentials

No registration needed — use this pre-made account:

| Field    | Value                |
|----------|----------------------|
| Email    | `test@uchicago.edu`  |
| Password | `test`               |

---

## Stopping the Server

Press `Ctrl + C` in the terminal.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `node: command not found` | Install Node.js from https://nodejs.org |
| Port 3000 already in use | Open `.env` and add `PORT=3001`, then visit http://localhost:3001 |
| Login not working | Password is just `test` (no capitals) |
