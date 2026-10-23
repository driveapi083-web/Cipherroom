import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import nodeCrypto from 'node:crypto';
import { createApp } from '../server.js';
import {
  CHUNK_SIZE, MIN_ITERATIONS, PBKDF2_ITERATIONS, b64u, decryptChunk, decryptMessage, deriveKeys,
  encryptChunk, encryptMessage, generatePassphrase, passwordStrength, randomBytes, randomToken,
} from '../public/crypto.js';
import { IntegrityTracker } from '../public/integrity.js';

let app, port;
const base = () => `http://127.0.0.1:${port}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  app = createApp({ maxClients: 3, createPerHour: 1000 });
  port = (await app.listen(0, '127.0.0.1')).port;
});
after(async () => {
  await app.close();
});

/* ---------- helpers ---------- */

async function api(method, p, body, headers = {}) {
  const res = await fetch(base() + p, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* none */ }
  return { status: res.status, data, headers: res.headers };
}

/** A room with a random key: skips the slow password stretching for speed. */
async function fastRoom() {
  const salt = b64u(randomBytes(16));
  const auth = randomToken();
  const hostToken = randomToken();
  const key = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const r = await api('POST', '/api/rooms', { salt, iterations: PBKDF2_ITERATIONS, auth, hostToken });
  assert.equal(r.status, 201);
  return { id: r.data.id, key, auth, hostToken, salt };
}

/** A room made exactly the way the browser does it, from a real password. */
async function realRoom(password) {
  const salt = b64u(randomBytes(16));
  const { key, auth } = await deriveKeys(password, salt);
  const hostToken = randomToken();
  const r = await api('POST', '/api/rooms', { salt, iterations: PBKDF2_ITERATIONS, auth, hostToken });
  assert.equal(r.status, 201);
  return { id: r.data.id, key, auth, hostToken, salt };
}

function connect() {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  const inbox = [];
  const waiters = [];
  let closeCode = null;
  const closed = new Promise((resolve) => ws.addEventListener('close', (e) => { closeCode = e.code; resolve(e.code); }));
  ws.addEventListener('message', (e) => {
    const m = JSON.parse(e.data);
    const i = waiters.findIndex((w) => w.pred(m));
    if (i >= 0) waiters.splice(i, 1)[0].resolve(m);
    else inbox.push(m);
  });
  const opened = new Promise((resolve, reject) => { ws.addEventListener('open', resolve); ws.addEventListener('error', reject); });
  const next = (pred = () => true, ms = 5000) => {
    const i = inbox.findIndex(pred);
    if (i >= 0) return Promise.resolve(inbox.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout waiting for message')), ms);
      waiters.push({ pred, resolve: (m) => { clearTimeout(t); resolve(m); } });
    });
  };
  const type = (t) => (m) => m.t === t;
  return { ws, opened, next, type, closed, send: (o) => ws.send(JSON.stringify(o)), get closeCode() { return closeCode; }, inbox };
}

const hello = (room, name) => encryptMessage(room.key, room.id, { n: name, u: name }, 'hello');
const nameOf = async (room, h) => (await decryptMessage(room.key, room.id, h, 'hello')).n;

async function joinHost(room, name = 'host') {
  const c = connect();
  await c.opened;
  c.send({ t: 'join', room: room.id, auth: room.auth, hostToken: room.hostToken, hello: await hello(room, name) });
  return c;
}

async function joinGuest(room, ticket, { session, name = 'guest', auth } = {}) {
  const c = connect();
  await c.opened;
  c.send({ t: 'join', room: room.id, auth: auth ?? room.auth, ticket, session, hello: await hello(room, name) });
  return c;
}

async function newTicket(host) {
  host.send({ t: 'newticket' });
  return (await host.next((m) => m.t === 'ticket')).id;
}

async function hostWithReady(room, name) {
  const host = await joinHost(room, name);
  const ready = await host.next((m) => m.t === 'ready');
  return { host, ready };
}

// Runs `fn` against a separate server (e.g. with short timers), then switches back.
async function withApp(options, fn) {
  const other = createApp({ createPerHour: 1000, ...options });
  const saved = port;
  port = (await other.listen(0, '127.0.0.1')).port;
  try {
    await fn(other);
  } finally {
    port = saved;
    await other.close();
  }
}

/* ---------- crypto and integrity unit tests ---------- */

test('passphrase generator: format, uniqueness and always accepted as strong', () => {
  const p = generatePassphrase();
  assert.match(p, /^([a-z2-9]{4}-){4}[a-z2-9]{4}$/);
  assert.notEqual(p, generatePassphrase());
  for (let i = 0; i < 50; i++) assert.ok(passwordStrength(generatePassphrase()).ok);
});

test('password strength: weak, common, repetitive and predictable passwords are refused', () => {
  for (const weak of ['short1!', 'ami12345678', 'ami123456789012', 'mypassword2026!', 'aaaaaaaaaaaaaaa', 'abcdefghijkl', 'khulnabarisal22', '']) {
    assert.equal(passwordStrength(weak).ok, false, `should refuse "${weak}"`);
  }
  for (const strong of ['vT9#qL2$mX8!pR4z', 'blue-tiger-moon-river-castle-7']) {
    assert.equal(passwordStrength(strong).ok, true, `should accept "${strong}"`);
  }
});

test('encrypt/decrypt round-trip; wrong key, wrong room, wrong purpose and tampering all fail', async () => {
  const salt = b64u(randomBytes(16));
  const { key } = await deriveKeys('correct horse battery', salt);
  const { key: other } = await deriveKeys('wrong horse battery', salt);
  const sealed = await encryptMessage(key, 'room-A', { n: 'ann', t: 'héllo বাংলা 🔒' });

  assert.deepEqual(await decryptMessage(key, 'room-A', sealed), { n: 'ann', t: 'héllo বাংলা 🔒' });
  assert.equal(await decryptMessage(other, 'room-A', sealed), null);
  assert.equal(await decryptMessage(key, 'room-B', sealed), null, 'message must be bound to its room');
  assert.equal(await decryptMessage(key, 'room-A', sealed, 'hello'), null, 'a message must not pass as a hello');
  const flipped = { ...sealed, ct: (sealed.ct[0] === 'A' ? 'B' : 'A') + sealed.ct.slice(1) };
  assert.equal(await decryptMessage(key, 'room-A', flipped), null);
});

test('key derivation refuses unsafe settings from a server', async () => {
  const salt = b64u(randomBytes(16));
  await assert.rejects(() => deriveKeys('some long password here', salt, 1000), /unsafe/);
  await assert.rejects(() => deriveKeys('some long password here', salt, MIN_ITERATIONS - 1), /unsafe/);
  await assert.rejects(() => deriveKeys('some long password here', salt, 50_000_000), /unsafe/);
  await assert.rejects(() => deriveKeys('some long password here', 'AAAA'), /bad salt/);
});

test('file chunks are bound to their position and count', async () => {
  const key = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const data = randomBytes(1000);
  const sealed = await encryptChunk(key, 'room', 'fileid0123456789', 2, 5, data);
  assert.deepEqual(await decryptChunk(key, 'room', 'fileid0123456789', 2, 5, sealed), data);
  assert.equal(await decryptChunk(key, 'room', 'fileid0123456789', 3, 5, sealed), null, 'reordered chunk');
  assert.equal(await decryptChunk(key, 'room', 'fileid0123456789', 2, 6, sealed), null, 'wrong chunk count');
  assert.equal(await decryptChunk(key, 'room', 'otherfile0123456', 2, 5, sealed), null, 'chunk from another file');
  assert.equal(await decryptChunk(key, 'other', 'fileid0123456789', 2, 5, sealed), null, 'chunk from another room');
});

test('integrity tracker spots repeated, reordered and dropped messages', () => {
  const t = new IntegrityTracker();
  assert.equal(t.checkId(5), 'ok'); // baseline
  assert.equal(t.checkId(6), 'ok');
  assert.equal(t.checkId(8), 'gap');
  assert.equal(t.checkId(8), 'replay');
  assert.equal(t.checkId(7), 'replay');

  assert.equal(t.checkSeq('ann', 1), 'ok');
  assert.equal(t.checkSeq('ann', 2), 'ok');
  assert.equal(t.checkSeq('ann', 2), 'duplicate');
  assert.equal(t.checkSeq('ann', 4), 'gap');
  assert.equal(t.checkSeq('bob', 7), 'ok'); // first one seen sets the baseline
  assert.equal(t.checkSeq('bob', 'x'), 'invalid');
  assert.equal(t.checkSeq(undefined, 1), 'invalid');
});

/* ---------- server: basics ---------- */

test('security headers and static pages', async () => {
  const r = await fetch(base() + '/');
  assert.equal(r.status, 200);
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /img-src 'self' blob:/);
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  assert.equal((await fetch(base() + '/r/anything')).status, 200);
  assert.equal((await fetch(base() + '/integrity.js')).status, 200);
  assert.equal((await fetch(base() + '/etc/passwd')).status, 404);
  assert.equal((await fetch(base() + '/../server.js')).status, 404);
});

test('room creation validates input', async () => {
  const salt = b64u(randomBytes(16));
  const ok = { salt, iterations: PBKDF2_ITERATIONS, auth: randomToken(), hostToken: randomToken() };
  assert.equal((await api('POST', '/api/rooms', { ...ok, iterations: 1000 })).status, 400);
  assert.equal((await api('POST', '/api/rooms', { ...ok, iterations: MIN_ITERATIONS - 1 })).status, 400);
  assert.equal((await api('POST', '/api/rooms', { ...ok, auth: 'short' })).status, 400);
  assert.equal((await api('POST', '/api/rooms', { ...ok, salt: '!!!' })).status, 400);
  const res = await fetch(base() + '/api/rooms', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify(ok) });
  assert.equal(res.status, 415);
});

/* ---------- full flow, with a real password ---------- */

test('full flow: password, personal link, chat, join/leave events, server holds only ciphertext', async () => {
  const pw = 'a-strong-test-password';
  const room = await realRoom(pw);

  const { host, ready: hostReady } = await hostWithReady(room, 'hostNick');
  assert.equal(hostReady.isHost, true);
  assert.equal(hostReady.online, 1);
  const ticket = await newTicket(host);

  // A guest derives the same key from the public salt + password.
  const info = await api('GET', `/api/rooms/${room.id}`);
  assert.equal(info.status, 200);
  const keys = await deriveKeys(pw, info.data.salt, info.data.iterations);
  const guestRoom = { ...room, key: keys.key, auth: keys.auth };
  const guest = await joinGuest(guestRoom, ticket, { name: 'guestNick' });
  const guestReady = await guest.next((m) => m.t === 'ready');
  assert.equal(guestReady.isHost, false);
  assert.equal(guestReady.online, 2);
  assert.equal(typeof guestReady.session, 'string');
  assert.equal(guestReady.peers.length, 1);
  assert.equal(await nameOf(room, guestReady.peers[0].hello), 'hostNick');

  const joined = await host.next((m) => m.t === 'joined');
  assert.equal(await nameOf(room, joined.hello), 'guestNick');
  assert.equal(joined.online, 2);

  const secret = 'meet at the old bridge at 9pm';
  const sealed = await encryptMessage(keys.key, room.id, { n: 'guestNick', u: 'g1', t: secret, s: 1 });
  guest.send({ t: 'msg', ...sealed });
  const got = await host.next((m) => m.t === 'msg');
  assert.equal((await decryptMessage(room.key, room.id, got.m)).t, secret);
  await guest.next((m) => m.t === 'msg');

  // Everything the server holds is ciphertext or public metadata.
  const held = JSON.stringify(app.store.open(room.id), (k, v) => (k === 'conn' || k === 'timer' ? undefined : v));
  for (const needle of [secret, 'guestNick', 'hostNick', pw]) assert.ok(!held.includes(needle), `server must not hold "${needle}"`);

  // A second guest with their own link sees the encrypted history.
  const ticket2 = await newTicket(host);
  const late = await joinGuest(guestRoom, ticket2, { name: 'lateNick' });
  const lateReady = await late.next((m) => m.t === 'ready');
  assert.equal(lateReady.history.length, 1);
  assert.equal((await decryptMessage(room.key, room.id, lateReady.history[0])).t, secret);

  late.send({ t: 'leave' });
  const left = await host.next((m) => m.t === 'left');
  assert.equal(left.online, 2);

  for (const c of [host, guest]) c.ws.close();
  await Promise.all([host.closed, guest.closed]);
});

/* ---------- who may enter ---------- */

test('wrong password, missing ticket and unknown ticket are all refused', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const ticket = await newTicket(host);

  const badPw = await joinGuest(room, ticket, { auth: randomToken() });
  assert.equal((await badPw.next((m) => m.t === 'error')).code, 'bad_credentials');
  assert.equal(await badPw.closed, 4003);

  const noTicket = await joinGuest(room, undefined);
  assert.equal((await noTicket.next((m) => m.t === 'error')).code, 'ticket_required');

  const fake = await joinGuest(room, randomToken(16));
  assert.equal((await fake.next((m) => m.t === 'error')).code, 'ticket_invalid');

  const garbage = connect();
  await garbage.opened;
  garbage.send({ t: 'join', room: '../../etc', auth: 'x', hello: {} });
  assert.equal((await garbage.next((m) => m.t === 'error')).code, 'bad_request');
  host.ws.close();
});

test('only the host can create invite links', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const guest = await joinGuest(room, await newTicket(host));
  await guest.next((m) => m.t === 'ready');
  guest.send({ t: 'newticket' });
  await sleep(150);
  assert.ok(!guest.inbox.some((m) => m.t === 'ticket'));
  host.ws.close();
  guest.ws.close();
});

test('a personal link works once: coming back after leaving needs the host to say yes', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const ticket = await newTicket(host);

  const first = await joinGuest(room, ticket, { name: 'rakib' });
  await first.next((m) => m.t === 'ready');
  await host.next((m) => m.t === 'joined');
  first.send({ t: 'leave' });
  await first.closed;
  await host.next((m) => m.t === 'left');

  // Same link again: held outside until the host decides.
  const again = await joinGuest(room, ticket, { name: 'rakib' });
  await again.next((m) => m.t === 'pending');
  const knock = await host.next((m) => m.t === 'knock');
  assert.equal(await nameOf(room, knock.hello), 'rakib');
  assert.ok(!again.inbox.some((m) => m.t === 'ready' || m.t === 'msg'), 'must not see anything while waiting');

  // Host says no.
  host.send({ t: 'deny', c: knock.c });
  await again.next((m) => m.t === 'denied');
  assert.equal(await again.closed, 4005);

  // Tries again; this time the host says yes.
  const third = await joinGuest(room, ticket, { name: 'rakib' });
  await third.next((m) => m.t === 'pending');
  const knock2 = await host.next((m) => m.t === 'knock');
  host.send({ t: 'admit', c: knock2.c });
  const ready = await third.next((m) => m.t === 'ready');
  assert.equal(typeof ready.session, 'string');

  // A dropped connection can come straight back with the session, no permission needed.
  third.ws.close();
  await third.closed;
  await host.next((m) => m.t === 'left');
  const resumed = await joinGuest(room, ticket, { name: 'rakib', session: ready.session });
  await resumed.next((m) => m.t === 'ready'); // would time out if it were held at the door
  const back = await host.next((m) => m.t === 'joined' && m.back === 1);
  assert.equal(await nameOf(room, back.hello), 'rakib');

  // Someone else using the same link, without that session, has to ask the host.
  const stranger = await joinGuest(room, ticket, { name: 'stranger' });
  await stranger.next((m) => m.t === 'pending');
  const knock3 = await host.next((m) => m.t === 'knock');
  assert.equal(await nameOf(room, knock3.hello), 'stranger');
  host.send({ t: 'deny', c: knock3.c });
  await stranger.next((m) => m.t === 'denied');

  host.ws.close();
  resumed.ws.close();
});

test('after the grace period a dropped guest also needs permission to return', () =>
  withApp({ graceMs: 400 }, async () => {
    const room = await fastRoom();
    const { host } = await hostWithReady(room);
    const ticket = await newTicket(host);
    const guest = await joinGuest(room, ticket);
    const ready = await guest.next((m) => m.t === 'ready');
    guest.ws.close();
    await guest.closed;
    await sleep(700); // longer than the grace period

    const late = await joinGuest(room, ticket, { session: ready.session });
    await late.next((m) => m.t === 'pending');
    host.ws.close();
  }));

test('room fills up at the configured limit (people waiting outside do not count)', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const guests = [];
  for (let i = 0; i < 2; i++) {
    const g = await joinGuest(room, await newTicket(host));
    await g.next((m) => m.t === 'ready');
    guests.push(g);
  }
  const extra = await joinGuest(room, await newTicket(host));
  assert.equal((await extra.next((m) => m.t === 'error')).code, 'room_full');
  [host, ...guests].forEach((c) => c.ws.close());
});

/* ---------- host leaving and deleting ---------- */

test('only the host can delete; deleting kicks everyone, erases the room and kills the links', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const guest = await joinGuest(room, await newTicket(host));
  await guest.next((m) => m.t === 'ready');

  host.send({ t: 'msg', ...(await encryptMessage(room.key, room.id, { n: 'x', u: 'x', t: 'bye', s: 1 })) });
  await guest.next((m) => m.t === 'msg');

  guest.send({ t: 'delete' });
  assert.equal((await guest.next((m) => m.t === 'error')).code, 'forbidden');
  assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 200, 'guest delete must not work');

  assert.ok(app.store.open(room.id));
  host.send({ t: 'delete' });
  assert.equal((await guest.next((m) => m.t === 'deleted')).reason, 'host_deleted');
  assert.equal(await guest.closed, 4000);

  assert.equal(app.store.open(room.id), null, 'room must be gone from memory');
  assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 404);
  const again = await joinHost(room);
  assert.equal((await again.next((m) => m.t === 'error')).code, 'not_found');
});

test('REST delete needs the host token', async () => {
  const room = await fastRoom();
  assert.equal((await api('DELETE', `/api/rooms/${room.id}`)).status, 403);
  assert.equal((await api('DELETE', `/api/rooms/${room.id}`, null, { 'X-Host-Token': randomToken() })).status, 403);
  assert.equal((await api('DELETE', `/api/rooms/${room.id}`, null, { 'X-Host-Token': room.hostToken })).status, 200);
  assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 404);
});

test('when the host leaves, the room ends for everyone straight away', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const guest = await joinGuest(room, await newTicket(host));
  await guest.next((m) => m.t === 'ready');
  const waiting = await joinGuest(room, await newTicket(host)); // a second guest, then...
  await waiting.next((m) => m.t === 'ready');

  host.send({ t: 'leave' });
  assert.equal((await guest.next((m) => m.t === 'deleted')).reason, 'host_left');
  assert.equal((await waiting.next((m) => m.t === 'deleted')).reason, 'host_left');
  assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 404);
  assert.equal(app.store.open(room.id), null);
});

test('if the host drops and does not come back in time, the room ends; if they return, it survives', () =>
  withApp({ graceMs: 400 }, async (short) => {
    const room = await fastRoom();
    let { host } = await hostWithReady(room);
    const guest = await joinGuest(room, await newTicket(host));
    await guest.next((m) => m.t === 'ready');

    // Host's connection drops and returns inside the grace period.
    host.ws.close();
    await host.closed;
    await guest.next((m) => m.t === 'host_away');
    await sleep(150);
    ({ host } = await hostWithReady(room));
    const back = await guest.next((m) => m.t === 'joined' && m.host === 1);
    assert.equal(back.online, 2);
    await sleep(500);
    assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 200, 'room must survive a quick reconnect');

    // Now the host disappears for good.
    host.ws.close();
    await guest.next((m) => m.t === 'host_away');
    assert.equal((await guest.next((m) => m.t === 'deleted', 3000)).reason, 'host_left');
    assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 404);
    assert.equal(short.store.open(room.id), null);
  }));

/* ---------- messages ---------- */

test('malformed messages are refused', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  host.send({ t: 'msg', iv: 'bad', ct: 'bad' });
  assert.equal((await host.next((m) => m.t === 'error')).code, 'bad_message');
  host.send({ t: 'msg', iv: b64u(randomBytes(12)), ct: 'A'.repeat(20000) });
  assert.equal((await host.next((m) => m.t === 'error')).code, 'bad_message');
  host.ws.close();
});

/* ---------- files ---------- */

async function upload(c, room, fid, data) {
  const n = Math.ceil(data.length / CHUNK_SIZE);
  for (let i = 0; i < n; i++) {
    const sealed = await encryptChunk(room.key, room.id, fid, i, n, data.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE));
    c.send({ t: 'fchunk', f: fid, i, n, ...sealed });
  }
  return n;
}

test('encrypted file transfer: upload, download, reassemble and verify', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const guest = await joinGuest(room, await newTicket(host));
  await guest.next((m) => m.t === 'ready');

  const data = new Uint8Array(nodeCrypto.randomBytes(150_000)); // 3 chunks
  const fid = randomToken(12);
  const n = await upload(host, room, fid, data);
  assert.equal(n, 3);
  await host.next((m) => m.t === 'fdone' && m.f === fid);

  // The server holds only ciphertext.
  const stored = app.store.getFile(room.id, fid);
  assert.ok(stored.complete);
  assert.ok(!Buffer.from(stored.chunks[0].ct, 'base64url').includes(data.subarray(0, 64)));

  guest.send({ t: 'fget', f: fid });
  const parts = new Array(n);
  for (let k = 0; k < n; k++) {
    const m = await guest.next((x) => x.t === 'fchunk' && x.f === fid, 8000);
    assert.equal(m.n, n);
    parts[m.i] = await decryptChunk(room.key, room.id, fid, m.i, m.n, m);
    assert.ok(parts[m.i], 'chunk must verify');
  }
  assert.deepEqual(Buffer.concat(parts), Buffer.from(data));

  // Unknown files are reported as missing.
  guest.send({ t: 'fget', f: randomToken(12) });
  await guest.next((m) => m.t === 'fmissing');

  // Files vanish with the room.
  assert.ok(app.store.fileBytes > 0);
  host.send({ t: 'delete' });
  await guest.next((m) => m.t === 'deleted');
  assert.equal(app.store.getFile(room.id, fid), null);
});

test('file storage limits: refused when the room is full, space freed by abandoned uploads and room deletion', () =>
  withApp({ roomFileBytes: 100_000 }, async (short) => {
    const room = await fastRoom();
    const { host } = await hostWithReady(room);
    const data = new Uint8Array(nodeCrypto.randomBytes(3 * CHUNK_SIZE)); // 3 chunks, about 196 KB: too big
    const fid = randomToken(12);
    await upload(host, room, fid, data);
    const err = await host.next((m) => m.t === 'error' && m.code === 'storage_full');
    assert.equal(err.f, fid);

    // Walking away mid-upload frees the partial file.
    assert.ok(short.store.fileBytes > 0);
    host.ws.close();
    await host.closed;
    await sleep(100);
    assert.equal(short.store.fileBytes, 0);
  }));

test('bad file requests are refused', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const sealed = await encryptChunk(room.key, room.id, 'fileid0123456789', 0, 1, randomBytes(10));
  host.send({ t: 'fchunk', f: 'x', i: 0, n: 1, ...sealed });
  host.send({ t: 'fchunk', f: 'fileid0123456789', i: 5, n: 1, ...sealed });
  host.send({ t: 'fchunk', f: 'fileid0123456789', i: 0, n: 9999, ...sealed });
  for (let k = 0; k < 3; k++) assert.equal((await host.next((m) => m.t === 'error')).code, 'bad_file');
  host.ws.close();
});

test("a room member cannot add chunks to someone else's upload", async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room);
  const guest = await joinGuest(room, await newTicket(host));
  await guest.next((m) => m.t === 'ready');

  const fid = randomToken(12);
  const first = await encryptChunk(room.key, room.id, fid, 0, 2, randomBytes(100));
  host.send({ t: 'fchunk', f: fid, i: 0, n: 2, ...first });
  await host.next((m) => m.t === 'fack');

  const intruder = await encryptChunk(room.key, room.id, fid, 1, 2, randomBytes(100));
  guest.send({ t: 'fchunk', f: fid, i: 1, n: 2, ...intruder });
  assert.equal((await guest.next((m) => m.t === 'error')).code, 'bad_file');

  // The owner can still finish their own upload.
  const real = await encryptChunk(room.key, room.id, fid, 1, 2, randomBytes(100));
  host.send({ t: 'fchunk', f: fid, i: 1, n: 2, ...real });
  await host.next((m) => m.t === 'fdone' && m.f === fid);
  host.ws.close();
  guest.ws.close();
});

test('typing notices are encrypted, reach everyone else, and are never stored', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room, 'hostNick');
  const guest = await joinGuest(room, await newTicket(host), { name: 'guestNick' });
  await guest.next((m) => m.t === 'ready');
  await host.next((m) => m.t === 'joined');

  const sealed = await encryptMessage(room.key, room.id, { n: 'guestNick', u: 'g1' }, 'typing');
  guest.send({ t: 'typing', ...sealed });
  const got = await host.next((m) => m.t === 'typing');
  assert.deepEqual(await decryptMessage(room.key, room.id, got, 'typing'), { n: 'guestNick', u: 'g1' });
  assert.equal(await decryptMessage(room.key, room.id, got, 'msg'), null, 'a typing notice cannot pass as a chat message');

  // The sender is not told about their own typing, and nothing is kept.
  assert.ok(!guest.inbox.some((m) => m.t === 'typing'));
  assert.equal(app.store.open(room.id).messages.length, 0);

  // Garbage is ignored, and flooding hits a limit without blocking real messages.
  guest.send({ t: 'typing', iv: 'x', ct: 'y' });
  for (let i = 0; i < 30; i++) guest.send({ t: 'typing', ...sealed });
  const chat = await encryptMessage(room.key, room.id, { n: 'guestNick', u: 'g1', t: 'still works', s: 1 });
  guest.send({ t: 'msg', ...chat });
  const m = await host.next((x) => x.t === 'msg');
  assert.equal((await decryptMessage(room.key, room.id, m.m)).t, 'still works');
  const typingSeen = host.inbox.filter((x) => x.t === 'typing').length;
  assert.ok(typingSeen < 30, `typing flood should be limited (saw ${typingSeen})`);

  host.ws.close();
  guest.ws.close();
});

test('a reply and its quote travel inside the encrypted message', async () => {
  const room = await fastRoom();
  const { host } = await hostWithReady(room, 'hostNick');
  const quoted = 'the quoted words should stay private';
  const sealed = await encryptMessage(room.key, room.id, { n: 'hostNick', u: 'h1', t: 'agreed', s: 1, r: { i: 1, n: 'guestNick', q: quoted } });
  host.send({ t: 'msg', ...sealed });
  const got = await host.next((m) => m.t === 'msg');
  const p = await decryptMessage(room.key, room.id, got.m);
  assert.deepEqual(p.r, { i: 1, n: 'guestNick', q: quoted });
  assert.ok(!JSON.stringify(app.store.open(room.id)).includes(quoted));
  host.ws.close();
});

/* ---------- one-time rooms ---------- */

test('room is erased once everyone has left; reconnecting in time keeps it', () =>
  withApp({ graceMs: 400, unclaimedMs: 5000 }, async (short) => {
    const room = await fastRoom();
    const { host } = await hostWithReady(room);
    host.send({ t: 'msg', ...(await encryptMessage(room.key, room.id, { n: 'a', u: 'a', t: 'hello', s: 1 })) });
    await host.next((m) => m.t === 'msg');

    // Drop and come back inside the grace period: room and history survive.
    host.ws.close();
    await host.closed;
    await sleep(150);
    const { host: again, ready } = await hostWithReady(room);
    assert.equal(ready.history.length, 1);
    await sleep(500); // longer than the original grace period
    assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 200);

    // Leave for good: the room stops existing.
    again.ws.close();
    await again.closed;
    await sleep(800);
    assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 404);
    assert.equal(short.store.open(room.id), null, 'history must be gone from memory');
    const late = await joinHost(room);
    assert.equal((await late.next((m) => m.t === 'error')).code, 'not_found');
  }));

test('a room nobody ever enters expires on its own', () =>
  withApp({ graceMs: 400, unclaimedMs: 800 }, async (short) => {
    const room = await fastRoom();
    assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 200);
    await sleep(1200);
    assert.equal((await api('GET', `/api/rooms/${room.id}`)).status, 404);
    assert.equal(short.store.count(), 0);
  }));

/* ---------- transport hardening ---------- */

test('cross-site WebSocket upgrade (bad Origin) is refused', async () => {
  const status = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: '/ws',
      headers: {
        Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': randomToken(16).slice(0, 22) + '==', Origin: 'https://evil.example',
      },
    });
    req.on('response', (res) => resolve(res.statusCode));
    req.on('upgrade', () => resolve(101));
    req.on('error', reject);
    req.end();
  });
  assert.equal(status, 403);
});

test('WebSocket layer rejects unmasked frames and binary frames', async () => {
  const handshake = () => new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(
        'GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n' +
        'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
      );
    });
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (buf.includes('\r\n\r\n')) { sock.removeAllListeners('data'); resolve({ sock, buf }); }
    });
    sock.on('error', reject);
  });

  const { sock, buf } = await handshake();
  assert.match(buf, /101 Switching Protocols/);
  assert.match(buf, /s3pPLMBiTxaQ9kYGzzhZRbK\+xOo=/); // RFC 6455 example accept value
  const closed = new Promise((resolve) => sock.on('close', resolve));
  sock.write(Buffer.from([0x81, 0x02, 0x68, 0x69])); // unmasked text frame "hi"
  await closed;

  const second = await handshake();
  const closed2 = new Promise((resolve) => second.sock.on('close', resolve));
  second.sock.write(Buffer.from([0x82, 0x81, 0, 0, 0, 0, 0x01])); // masked binary frame
  await closed2;
});

test('PWA files are served with the right types and the CSP allows them', async () => {
  const m = await fetch(base() + '/manifest.webmanifest');
  assert.equal(m.status, 200);
  assert.match(m.headers.get('content-type'), /manifest\+json/);
  const manifest = await m.json();
  assert.equal(manifest.display, 'standalone');
  for (const icon of manifest.icons) assert.equal((await fetch(base() + icon.src)).status, 200);
  assert.equal((await fetch(base() + '/sw.js')).status, 200);
  assert.equal((await fetch(base() + '/apple-touch-icon.png')).status, 200);
  const csp = (await fetch(base() + '/')).headers.get('content-security-policy');
  assert.match(csp, /manifest-src 'self'/);
  assert.match(csp, /worker-src 'self'/);
});
