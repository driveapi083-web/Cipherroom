// All cryptography happens here, in the browser. Shared with the test-suite.
//
//   password --PBKDF2-SHA256 (600k, per-room salt)--> master secret
//   master --HKDF--> auth token  (sent to the server, proves you know the password)
//   master --HKDF--> AES-256-GCM key (never leaves this device)
//
// The server only ever stores a hash of the auth token and AES-GCM ciphertext.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;
export const MIN_ITERATIONS = 600_000; // a room (or server) asking for less is refused
export const MAX_ITERATIONS = 5_000_000;
export const CHUNK_SIZE = 64 * 1024; // file chunk size before encryption
export const MAX_FILE_BYTES = 10 * 1024 * 1024;

// 31 symbols without look-alikes (no i, l, o, 0, 1)
const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export function b64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const randomToken = (bytes = 32) => b64u(randomBytes(bytes));

/* ------------------------------------------------------------ passwords */

const COMMON = [
  'password', 'passw0rd', 'qwerty', 'asdfgh', 'zxcvb', 'letmein', 'welcome', 'iloveyou', 'admin', 'abc123',
  '123456', '12345', '1234', '111111', '000000', 'dhaka', 'bangla', 'monkey', 'dragon', 'football', 'secret',
  'changeme', 'cipherroom',
];

function hasSequence(s, minRun = 4) {
  const chars = [...s.toLowerCase()];
  let up = 1;
  let down = 1;
  for (let i = 1; i < chars.length; i++) {
    const d = chars[i].charCodeAt(0) - chars[i - 1].charCodeAt(0);
    const alnum = /[a-z0-9]/.test(chars[i]);
    up = alnum && d === 1 ? up + 1 : 1;
    down = alnum && d === -1 ? down + 1 : 1;
    if (up >= minRun || down >= minRun) return true;
  }
  return false;
}

/**
 * A conservative estimate, not a guarantee. Rejects short, common, repetitive and
 * patterned passwords; everything the app generates for you passes.
 */
export function passwordStrength(password) {
  const p = String(password).trim();
  const weak = (reason) => ({ ok: false, bits: 0, reason });
  if (p.length < 12) return weak('Too short. Use at least 12 characters, or press New password.');
  const lower = p.toLowerCase();
  if (COMMON.some((w) => lower.includes(w))) return weak('Too guessable: it contains a common word or number pattern.');
  if (/(.)\1{3,}/.test(p)) return weak('Too repetitive: avoid repeating the same character.');
  if (hasSequence(p)) return weak('Too predictable: avoid sequences like 1234 or abcd.');

  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[ -/:-@[-`{-~]/.test(p)) pool += 33;
  if (/[^\x00-\x7f]/.test(p)) pool += 100;
  const distinct = new Set(p).size;
  const effective = distinct + 0.25 * (p.length - distinct);
  const bits = effective * Math.log2(pool || 1) * 0.8;
  if (bits < 64) return weak('Too weak. Use the generated password, or a long mix of random words, numbers and symbols.');
  return { ok: true, bits, reason: '' };
}

/** e.g. "k7mq-x2vd-hr9t-p4wn-e8bz": 20 symbols, about 99 bits of entropy. */
export function generatePassphrase(groups = 5, size = 4) {
  for (;;) {
    const parts = [];
    for (let g = 0; g < groups; g++) {
      let part = '';
      while (part.length < size) {
        const [b] = randomBytes(1);
        if (b < 248) part += ALPHABET[b % 31]; // 248 = 31 * 8: rejection sampling keeps it uniform
      }
      parts.push(part);
    }
    const candidate = parts.join('-');
    if (passwordStrength(candidate).ok) return candidate; // skip the rare accidental pattern
  }
}

/* ----------------------------------------------------------------- keys */

export async function deriveKeys(password, saltB64u, iterations = PBKDF2_ITERATIONS) {
  // Never let a server talk us into weak (or absurdly expensive) key stretching.
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error('unsafe key settings');
  }
  if (typeof saltB64u !== 'string' || unb64u(saltB64u).length !== 16) throw new Error('bad salt');

  const pw = enc.encode(password.trim().normalize('NFKC'));
  const base = await subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
  const master = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: unb64u(saltB64u), iterations },
    base,
    256,
  );
  const hkdf = await subtle.importKey('raw', master, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const params = (label) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(label) });

  const authBits = await subtle.deriveBits(params('cipherroom/auth/v1'), hkdf, 256);
  const key = await subtle.deriveKey(params('cipherroom/enc/v1'), hkdf, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  return { key, auth: b64u(new Uint8Array(authBits)) };
}

/* ------------------------------------------------------------- messages */
// The room id and the purpose ("msg", "hello") are bound in as additional
// authenticated data, so a ciphertext cannot be replayed in another room or role.

export async function encryptMessage(key, roomId, payload, purpose = 'msg') {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(`${roomId}|${purpose}`) },
    key,
    enc.encode(JSON.stringify(payload)),
  );
  return { iv: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}

/** Returns the payload, or null if the message is forged, corrupted or from another room. */
export async function decryptMessage(key, roomId, { iv, ct }, purpose = 'msg') {
  try {
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: unb64u(iv), additionalData: enc.encode(`${roomId}|${purpose}`) },
      key,
      unb64u(ct),
    );
    return JSON.parse(dec.decode(plain));
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------- file chunks */
// Each chunk is bound to its file id, its position and the total chunk count, so
// the server cannot reorder, drop, or splice chunks without detection.

const chunkAad = (roomId, fid, i, n) => enc.encode(`${roomId}|file|${fid}|${i}|${n}`);

export async function encryptChunk(key, roomId, fid, i, n, bytes) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: chunkAad(roomId, fid, i, n) }, key, bytes);
  return { iv: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}

/** Returns the chunk bytes, or null if it fails verification. */
export async function decryptChunk(key, roomId, fid, i, n, { iv, ct }) {
  try {
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(iv), additionalData: chunkAad(roomId, fid, i, n) }, key, unb64u(ct));
    return new Uint8Array(plain);
  } catch {
    return null;
  }
}
