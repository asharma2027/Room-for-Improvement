# Room for Improvement — Instructor Setup

## Starting the App

### Mac
1. Open **Terminal** (search "Terminal" in Spotlight)
2. Type `bash ` (with a space after it), then drag the file **`Start - Mac.command`** into the Terminal window — it will fill in the path automatically
3. Press **Enter**

### Windows
Double-click **`Start - Windows.bat`**

The launcher will automatically:
- Install Node.js if you don't have it
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

Close the terminal window. The server stops automatically.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Mac: "permission denied" or "cannot be opened" | Use the Terminal drag-and-drop method above |
| Port 3000 already in use | Open `.env` in the project root and change `APP_URL=http://localhost:3001`, then relaunch |
| Node.js install fails | Install manually from [nodejs.org](https://nodejs.org) (LTS version), then relaunch |
