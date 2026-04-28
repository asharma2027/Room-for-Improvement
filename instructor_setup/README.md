# Room for Improvement — Instructor Setup

## Starting the App

**Mac:** Double-click `Start - Mac.command`

**Windows:** Double-click `Start - Windows.bat`

That's it. The launcher will:
- Install Node.js automatically if you don't have it
- Install all other dependencies
- Start the server
- Open the site in your browser

---

## Login

| Field    | Value               |
|----------|---------------------|
| Email    | `test@uchicago.edu` |
| Password | `test`              |

---

## Stopping the App

Close the terminal window that opened. The server stops automatically.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Mac says "cannot be opened because it is from an unidentified developer" | Right-click the file → Open → Open |
| Port 3000 already in use | Open `.env` in the project root and change `APP_URL=http://localhost:3001`, then relaunch |
| Node.js install fails | Install manually from [nodejs.org](https://nodejs.org) (LTS version), then relaunch |
