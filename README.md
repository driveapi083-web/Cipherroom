# CipherRoom

Private, open-source, end-to-end encrypted, **one-time** chat rooms. Create a room, send each guest a personal one-time link and the password, and chat (text, photos and files). When the host leaves, or everyone has left, the room, its messages, its files and its links are erased and cease to exist. Every chat starts with brand-new links.

- **Zero dependencies.** Plain Node.js (20+) on the server, plain JavaScript in the browser. No `npm install`.
- **End-to-end encrypted.** Encryption and decryption happen in the browser. The server only stores ciphertext.
- **Password plus personal link.** The link identifies the room and its guest, the password unlocks it. The password is never sent to the server, and weak passwords (short, common words, patterns like `1234`) are refused.
- **One link per person, and re-entry needs permission.** The host makes one one-time link per guest. After a guest leaves (Leave button, or closing the tab), their link no longer lets them straight back in: the host must press **Let in**. A page reload or a short network drop (60 seconds) does not count as leaving.
- **The host leaving ends the room.** If the host presses Leave or Delete, everyone is removed and everything is erased. If the host only drops off, guests see a warning and the room ends after 60 seconds unless the host returns.
- **One-time rooms, memory only.** Rooms live only in the server's memory and are never written to disk. When everyone has left the room is erased after a short grace period. A room nobody ever enters expires after 10 minutes, and restarting the server erases every room.
- **Encrypted photos and files.** Up to 10 MB per file and 50 MB per room, encrypted in the browser in 64 KB pieces. Photos are shrunk (and their hidden location data removed) before sending and shown in the chat; other files are download-only and are never opened automatically.
- **Join and leave notices**, and **warnings if the server repeats, reorders or silently drops messages** (checked with sequence numbers inside the encrypted messages).
- **No accounts, no tracking, no access logs.**

## Quick start

```bash
node server.js
# open http://localhost:3000
```

Requires Node.js 20 or newer. Nothing is stored on disk.

Browsers only allow the Web Crypto API on secure pages, so outside `localhost` you must serve the app over **HTTPS**. Opening it over plain `http://192.168.x.x` will show a "needs a secure connection" page.

## How to use

1. Open the site, choose a nickname, keep the generated password (or type your own: at least 12 characters, and not guessable) and click **Create private room**.
2. In the **Invite** window press **Create one-time link** once per person. Send each person their own link, and send the password through a **different channel**.
3. Guests open their link, enter the password, and chat. Up to 10 people per room by default.
4. When a guest leaves and later wants back in, you get a request at the top of the chat: **Let in** or **Deny**.
5. When you are done, press **Leave** (or **Delete room**). The room ends for everyone and is erased. Next time, create a new room.

Only the browser that created the room holds the host secret (kept in `localStorage`), so only that browser is the host. If the host browser data is lost, nobody can host that room, and it ends when the host connection drops.

## Install on a phone or computer (PWA)

Once the app is hosted on an HTTPS address, it can be installed like a normal app:

- **Android (Chrome):** open the link, menu (three dots), **Install app** / **Add to Home screen**.
- **iPhone (Safari):** open the link, Share button, **Add to Home Screen**.
- **Computer (Chrome/Edge):** click the install icon at the right of the address bar.

## One-click deploy on Render (free)

1. Put this folder in a GitHub repository (github.com, New repository, upload the files).
2. On render.com, create an account, then **New > Blueprint**, and choose that repository. `render.yaml` sets everything up.
3. After a minute you get an address like `https://cipherroom-xxxx.onrender.com`. That is your app.

The free plan sleeps after 15 minutes without traffic (the first visit afterwards takes about a minute to wake it) and does not keep files. That suits CipherRoom: rooms are memory-only and one-time by design, so nothing is lost that was meant to be kept. If the server sleeps or restarts, every room ends; just create a new one.

## Deploy

**Caddy (easiest HTTPS):** put your domain in `Caddyfile`, run `caddy run`, and start the app with `TRUST_PROXY=1 node server.js`.

**Docker:**

```bash
docker build -t cipherroom .
docker run -d --name cipherroom -p 127.0.0.1:3000:3000 -e TRUST_PROXY=1 cipherroom
```

Then put any HTTPS reverse proxy (Caddy, nginx, Cloudflare Tunnel) in front. The proxy must forward WebSocket upgrades and the original `Host` header.

### Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3000` | Port to listen on |
| `HOST` | `0.0.0.0` | Interface to bind |
| `TRUST_PROXY` | off | Set to `1` behind a reverse proxy so rate limits use `X-Forwarded-For` |
| `MAX_CLIENTS_PER_ROOM` | `10` | People allowed in one room at a time |
| `MAX_ROOMS` | `1000` | Rooms the server will hold |
| `MAX_HISTORY` | `2000` | Messages kept per live room (oldest are dropped) |
| `ROOM_GRACE_SECONDS` | `60` | How long an empty room, an absent host or a dropped guest has to come back |
| `ROOM_UNCLAIMED_MINUTES` | `10` | A room nobody enters is erased after this long |
| `ROOM_FILE_MB` | `50` | File storage per room |
| `MAX_TOTAL_FILE_MB` | `200` | File storage across all rooms. Files live in RAM: lower this on small hosts (the free Render plan has 512 MB) |
| `CREATE_PER_HOUR` | `20` | Rooms one IP may create per hour |

## How the encryption works

```
password + room salt --PBKDF2-SHA256, 600,000 rounds--> master secret
master secret --HKDF--> auth token   (sent to the server to prove you know the password)
master secret --HKDF--> AES-256-GCM key  (never leaves your device)
```

- Each message is `{nickname, text, sender id, counter}` encrypted with AES-256-GCM, a fresh random 96-bit nonce, and the room id plus the message purpose as authenticated data, so a message cannot be moved to another room or reused for another role.
- Files are cut into 64 KB chunks, each encrypted with AES-GCM and bound to the file id, its position and the chunk count, so the server cannot reorder, drop or splice chunks without detection. File names and types are inside encrypted messages.
- The browser refuses to join a room whose key settings are weaker than 600,000 PBKDF2 rounds, even if the server asks for it.
- The server stores a SHA-256 hash of the auth token, never the token itself, and never the key or password.
- Room ids are 128-bit random values, so links cannot be guessed.
- The generated password has about 99 bits of entropy. Anyone who gets a copy of the server data would have to brute-force the password offline against PBKDF2, so use the generated one or a long passphrase.

## What the server can and cannot see

| Can see | Cannot see |
| --- | --- |
| That a room exists, when it was created and last used | Message text, nicknames, file names and file contents |
| How many people are connected, and their IP addresses (in memory only) | The password or the encryption key |
| When messages and files arrive and roughly how big they are | Who said what |

## Limits you should know about

- **You trust the code the server delivers.** Like any web app, a malicious or compromised server could ship modified JavaScript. If this matters, host it yourself, and keep it patched. The code is small on purpose so it can be audited.
- **Anyone with a valid personal link and the password can enter**, and the first person to use a link gets in: if a link leaks before the guest uses it, a stranger who also has the password could take the place. Send links and password through different channels.
- **Inside the room, trust is shared.** Everyone with the password holds the same key, so nicknames are not verified and a member can pretend to be another member or disturb the sequence checks. Invite only people you trust.
- **Screenshots and photos of the screen cannot be blocked** by a website. Anyone in the room can keep what they see.
- **Erasing means dropping the room from the server's memory.** Nothing is written to disk, so there is nothing to recover from storage. Operating systems may swap memory to disk and a hosting provider could snapshot a machine, so this is strong but not a forensic guarantee. Anyone who already copied or screenshotted messages keeps them.
- **Metadata is not hidden:** timing, message sizes and IP addresses are visible to the server operator and network.
- Group chat uses one shared key. Changing who is in the room means creating a new room.

## Project layout

```
server.js          HTTP + WebSocket server, rate limiting, security headers
src/websocket.js   Dependency-free RFC 6455 WebSocket implementation
src/store.js       In-memory room storage
src/ratelimit.js   In-memory sliding-window limiter
public/            Browser app (crypto.js and integrity.js are shared with the tests)
test/              End-to-end tests: node --test
```

## Tests

```bash
npm test
```

## License

MIT. See `LICENSE`.
