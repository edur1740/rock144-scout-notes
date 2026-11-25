# R.O.C.K. Scout Notes

Scouting app for FRC Team 144 Operation Orange and Team 325 Respawn Robotics.
Scouts sign in on their phones, write notes on robots each match, and the whole team
sees every team's notes, events and the scouting schedule.

## What's in here

| Path | What it is |
|---|---|
| `public/` | The app itself (one page, plus icons, offline support and install files) |
| `netlify/functions/notes.mts` | The server: accounts, notes, events, schedule, alerts |
| `netlify.toml` | Netlify settings and security headers |
| `package.json` | The two Netlify libraries the server uses |
| `tests/` | Outside-attacker test suite (`sh tests/run-attacks.sh`, needs Node 22+) |

## Hosting

The app is built for **Netlify** (it uses Netlify Functions and Netlify Blobs for storage).

1. Create a Netlify project and connect this folder (GitHub, or drag and drop the folder).
2. In **Project configuration → Environment variables**, add:
   - `TEAM_CODE`: the code scouts need to make an account. Pick something hard to guess.
   - `ADMINS`: your username (comma-separate more). The first name listed becomes the owner.
3. Deploy, open the site, and create your account with the username you put in `ADMINS`.

No other setup is needed: the signing secret and phone-alert keys create themselves on first use.

Other hosts (Vercel, Cloudflare, your own server) would need the server file adapted,
since it stores data in Netlify Blobs.

## After launch

- Turn off "Let scouts make their own accounts" on the Accounts tab once everyone has joined.
- Change `TEAM_CODE` after each season and redeploy.
