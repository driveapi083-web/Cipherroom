import {
  CHUNK_SIZE,
  MAX_FILE_BYTES,
  MAX_ITERATIONS,
  MIN_ITERATIONS,
  PBKDF2_ITERATIONS,
  b64u,
  decryptChunk,
  decryptMessage,
  deriveKeys,
  encryptChunk,
  encryptMessage,
  generatePassphrase,
  passwordStrength,
  randomBytes,
  randomToken,
} from './crypto.js';
import { IntegrityTracker } from './integrity.js';

const app = document.getElementById('app');
const HOST_KEY = 'cipherroom.host';
const GUEST_KEY = 'cipherroom.guest';
const NICK_KEY = 'cipherroom.nick';
const MAX_TEXT = 2000;
const QUOTE_MAX = 100; // characters of the original message shown in a reply
const TYPING_GAP_MS = 3000; // send "typing" at most this often
const TYPING_SHOW_MS = 5000; // a typing notice disappears after this long
const MAX_TYPERS = 12;
const IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const AUTO_SHOW_IMAGE_BYTES = 2 * 1024 * 1024;
const TICKET_RE = /^[A-Za-z0-9_-]{22}$/;

/* ------------------------------------------------------------ DOM helpers */

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k in el && k !== 'list') el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = h('textarea', { value: text, class: 'offscreen' });
    document.body.append(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {
      /* ignore */
    }
    ta.remove();
    return ok;
  }
}

function copyButton(getText, label = 'Copy') {
  const btn = h('button', { class: 'btn', type: 'button' }, icon('copy'), label);
  btn.addEventListener('click', async () => {
    const ok = await copyText(getText());
    btn.replaceChildren(icon(ok ? 'check' : 'copy'), ok ? 'Copied' : 'Copy failed');
    setTimeout(() => btn.replaceChildren(icon('copy'), label), 1600);
  });
  return btn;
}

const ADJ = ['Quiet', 'Swift', 'Brave', 'Calm', 'Bright', 'Lucky', 'Gentle', 'Sharp'];
const ANIMAL = ['Fox', 'Owl', 'Otter', 'Heron', 'Lynx', 'Finch', 'Panda', 'Gecko'];
const pick = (list) => list[randomBytes(1)[0] % list.length];
const randomNick = () => pick(ADJ) + pick(ANIMAL);
const cleanNick = (s) => s.trim().slice(0, 24) || randomNick();
const safeName = (s) => String(s || 'file').replace(/[\u0000-\u001f\u007f\\/:*?"<>|]+/g, '_').slice(0, 80) || 'file';
const formatSize = (n) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

/* ------------------------------------------------ small browser storage */
// localStorage: the host secret of rooms you created.
// sessionStorage: your own personal invite ticket (and session) for this tab only.
// Closing the tab forgets the session, which is what makes "leaving" real.

function loadHostTokens() {
  try {
    return JSON.parse(localStorage.getItem(HOST_KEY) || '{}');
  } catch {
    return {};
  }
}
const getToken = (id) => loadHostTokens()[id] || null;
function saveToken(id, token) {
  try {
    localStorage.setItem(HOST_KEY, JSON.stringify({ ...loadHostTokens(), [id]: token }));
  } catch {
    /* storage unavailable */
  }
}
function dropToken(id) {
  try {
    const all = loadHostTokens();
    delete all[id];
    localStorage.setItem(HOST_KEY, JSON.stringify(all));
  } catch {
    /* ignore */
  }
}

function loadGuest(roomId) {
  try {
    return JSON.parse(sessionStorage.getItem(`${GUEST_KEY}.${roomId}`) || 'null');
  } catch {
    return null;
  }
}
function saveGuest(roomId, data) {
  try {
    sessionStorage.setItem(`${GUEST_KEY}.${roomId}`, JSON.stringify(data));
  } catch {
    /* ignore */
  }
}
// The nickname survives a page reload (same tab only), so you do not turn into someone else.
const loadNick = (roomId) => {
  try {
    return sessionStorage.getItem(`${NICK_KEY}.${roomId}`) || '';
  } catch {
    return '';
  }
};
function saveNick(roomId, nick) {
  try {
    sessionStorage.setItem(`${NICK_KEY}.${roomId}`, nick);
  } catch {
    /* ignore */
  }
}

function dropGuest(roomId) {
  try {
    sessionStorage.removeItem(`${NICK_KEY}.${roomId}`);
    sessionStorage.removeItem(`${GUEST_KEY}.${roomId}`);
  } catch {
    /* ignore */
  }
}

/* --------------------------------------------------------------------- api */

async function api(method, path, body, headers = {}) {
  const res = await fetch(path, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* no body */
  }
  return { ok: res.ok, status: res.status, data };
}

const ERRORS = {
  bad_credentials: 'Wrong password. Check it and try again.',
  not_found: 'This room no longer exists.',
  room_full: 'This room is full.',
  rate_limited: 'Too many attempts. Wait a few minutes and try again.',
  bad_request: 'The invite link looks broken.',
  ticket_required: 'This link needs a personal invite. Ask the host for a one-time link.',
  ticket_invalid: 'This invite link is not valid. Ask the host for a new one.',
  no_response: 'The host did not answer in time. Ask them to let you in and try again.',
  replaced: 'This room was opened in another window, so this one was disconnected.',
};

/* ------------------------------------------------------------------- views */

function brand() {
  return h('div', { class: 'brand' }, icon('lock'), h('span', {}, 'CipherRoom'));
}

function noticeCard(title, text, actionLabel = 'Create a new room', onAction = () => location.assign('/')) {
  document.title = 'CipherRoom';
  app.replaceChildren(
    h(
      'main',
      { class: 'page' },
      brand(),
      h(
        'section',
        { class: 'card center' },
        h('h1', {}, title),
        h('p', { class: 'lead' }, text),
        h('button', { class: 'btn primary', type: 'button', onclick: onAction }, actionLabel),
      ),
    ),
  );
}

function showUnsupported() {
  noticeCard(
    'This page needs a secure connection',
    'Browsers only allow encryption on https:// pages (or localhost). Open this site over HTTPS and try again.',
    'Reload',
  );
}

const HOW_IT_WORKS = [
  ['Your password never leaves this device.', 'Your browser stretches it with PBKDF2 (600,000 rounds) into an encryption key and a separate login token.'],
  ['Messages and files are sealed before they are sent.', 'AES-256-GCM, with a fresh random nonce each time. Even nicknames and file names are inside the ciphertext.'],
  ['The server only holds ciphertext.', 'It can see how many people are in a room and when things arrive, but not what they say or send.'],
  ['Every guest gets a personal one-time link.', 'After someone leaves, their link no longer lets them straight back in. They need your permission.'],
  ['Every room is one-time.', 'Rooms live only in the server memory, never on disk. When the host leaves, or everyone has left, the room, its messages and its files are erased and the link stops working.'],
  ['One honest limit.', 'You trust the server to deliver unmodified code. If that matters, host it yourself: it is open source.'],
];

function showHome() {
  document.title = 'CipherRoom: private encrypted chat rooms';

  const nick = h('input', { id: 'nick', maxlength: '24', value: randomNick(), autocomplete: 'off', spellcheck: false });
  const pass = h('input', {
    id: 'pass',
    class: 'mono key',
    value: generatePassphrase(),
    autocomplete: 'off',
    spellcheck: false,
    'aria-describedby': 'pass-hint pass-strength',
  });
  const strength = h('p', { class: 'strength', id: 'pass-strength', 'aria-live': 'polite' });
  const checkStrength = () => {
    const s = passwordStrength(pass.value);
    strength.textContent = s.ok ? 'Strong password.' : s.reason;
    strength.className = `strength ${s.ok ? 'ok' : 'bad'}`;
  };
  pass.addEventListener('input', checkStrength);
  checkStrength();

  const err = h('p', { class: 'error', role: 'alert' });
  const createLabel = [icon('lock'), 'Create private room'];
  const btn = h('button', { class: 'btn primary wide', type: 'submit' }, ...createLabel);

  const form = h(
    'form',
    {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        const password = pass.value.trim();
        const s = passwordStrength(password);
        if (!s.ok) {
          err.textContent = s.reason;
          return;
        }
        btn.disabled = true;
        btn.replaceChildren('Creating room…');
        try {
          const salt = b64u(randomBytes(16));
          const { key, auth } = await deriveKeys(password, salt);
          const hostToken = randomToken();
          const r = await api('POST', '/api/rooms', { salt, iterations: PBKDF2_ITERATIONS, auth, hostToken });
          if (!r.ok) throw new Error(r.data?.error || 'Could not create the room.');
          saveToken(r.data.id, hostToken);
          history.pushState(null, '', `/r/${r.data.id}`);
          startChat({ roomId: r.data.id, key, auth, hostToken, nick: cleanNick(nick.value), password, justCreated: true });
        } catch (ex) {
          err.textContent = ex.message || 'Something went wrong.';
          btn.disabled = false;
          btn.replaceChildren(...createLabel);
        }
      },
    },
    h('div', { class: 'field' }, h('label', { for: 'nick' }, 'Your nickname'), nick),
    h(
      'div',
      { class: 'field' },
      h('label', { for: 'pass' }, 'Room password'),
      pass,
      strength,
      h(
        'div',
        { class: 'row' },
        h(
          'button',
          {
            class: 'btn',
            type: 'button',
            onclick: () => {
              pass.value = generatePassphrase();
              checkStrength();
            },
          },
          icon('refresh'),
          'New password',
        ),
        copyButton(() => pass.value),
      ),
      h('p', { class: 'hint', id: 'pass-hint' }, 'Generated for you. Everyone you invite needs it, so share it in a different channel than the invite links. It cannot be recovered.'),
    ),
    err,
    btn,
  );

  app.replaceChildren(
    h(
      'main',
      { class: 'page' },
      brand(),
      h(
        'section',
        { class: 'card' },
        h('h1', {}, 'A chat room only the people you invite can read.'),
        h('p', { class: 'lead' }, 'Create a room, send each guest a one-time link and the password, and talk. When you leave, the room and everything in it is erased for good.'),
        form,
      ),
      h(
        'details',
        { class: 'how' },
        h('summary', {}, 'How it works'),
        h('dl', {}, HOW_IT_WORKS.map(([t, d]) => [h('dt', {}, t), h('dd', {}, d)])),
      ),
      h('footer', {}, 'Open source (MIT). No accounts, no tracking, no access logs.'),
    ),
  );
}

async function showJoin(roomId, { error = '', nickValue = '' } = {}) {
  document.title = 'Join a private room · CipherRoom';
  const info = await api('GET', `/api/rooms/${roomId}`);
  if (info.status === 404) {
    dropToken(roomId);
    dropGuest(roomId);
    return noticeCard('This room has ended', 'Rooms are one-time. Once the host leaves, or everyone has left, the room and its messages are erased and the link stops working. Ask for a new link.');
  }
  if (!info.ok) return noticeCard('Could not reach the room', info.data?.error || 'Try again in a moment.', 'Reload', () => location.reload());

  // Never trust the server to pick weak key settings for us.
  const it = info.data?.iterations;
  if (!Number.isInteger(it) || it < MIN_ITERATIONS || it > MAX_ITERATIONS || typeof info.data?.salt !== 'string') {
    return noticeCard('Unsafe room settings', 'This room uses weaker key settings than CipherRoom allows. Do not enter the password. Ask for a new room.', 'Go to start');
  }

  const hostToken = getToken(roomId);
  const guest = loadGuest(roomId);
  if (!hostToken && !guest?.ticket) {
    return noticeCard('This invite link is incomplete', 'Each guest needs a personal one-time link from the host. Ask the host to send you one.', 'Go to start');
  }

  const nick = h('input', { id: 'nick', maxlength: '24', value: nickValue || loadNick(roomId) || randomNick(), autocomplete: 'off', spellcheck: false });
  const pass = h('input', { id: 'pass', type: 'password', autocomplete: 'off', spellcheck: false, required: true });
  const err = h('p', { class: 'error', role: 'alert' }, error);
  const btn = h('button', { class: 'btn primary wide', type: 'submit' }, icon('lock'), 'Join room');

  const eye = h('button', { class: 'btn icon-only', type: 'button', title: 'Show or hide password', 'aria-label': 'Show or hide password' }, icon('eye'));
  eye.addEventListener('click', () => {
    const show = pass.type === 'password';
    pass.type = show ? 'text' : 'password';
    eye.replaceChildren(icon(show ? 'eyeoff' : 'eye'));
  });

  const form = h(
    'form',
    {
      class: 'stack',
      onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        btn.disabled = true;
        btn.replaceChildren('Unlocking…');
        try {
          const { key, auth } = await deriveKeys(pass.value, info.data.salt, it);
          startChat({ roomId, key, auth, hostToken, nick: cleanNick(nick.value), password: pass.value.trim(), justCreated: false });
        } catch {
          err.textContent = 'Could not derive the key in this browser.';
          btn.disabled = false;
          btn.replaceChildren(icon('lock'), 'Join room');
        }
      },
    },
    h('div', { class: 'field' }, h('label', { for: 'nick' }, 'Your nickname'), nick),
    h('div', { class: 'field' }, h('label', { for: 'pass' }, 'Room password'), h('div', { class: 'row tight' }, pass, eye)),
    err,
    btn,
  );

  const hostNote = hostToken
    ? h(
        'div',
        { class: 'host-note' },
        h('p', {}, 'You created this room from this browser.'),
        h('button', { class: 'btn danger', type: 'button', onclick: () => confirmDelete(async () => {
          const r = await api('DELETE', `/api/rooms/${roomId}`, null, { 'X-Host-Token': hostToken });
          if (r.ok || r.status === 404) {
            dropToken(roomId);
            noticeCard('Room deleted', 'The room and everything in it has been erased from the server.');
          }
        }) }, icon('trash'), 'Delete room'),
      )
    : null;

  app.replaceChildren(
    h(
      'main',
      { class: 'page' },
      brand(),
      h(
        'section',
        { class: 'card' },
        h('h1', {}, 'You have been invited to a private room'),
        h('p', { class: 'lead' }, 'Enter the password you received separately from this link. It is used only on your device.'),
        form,
        hostNote,
      ),
      h('footer', {}, 'Open source (MIT). The server cannot read this room.'),
    ),
  );
  pass.focus();
}

/* ------------------------------------------------------------------ dialogs */

function openDialog(...content) {
  const dlg = h('dialog', { class: 'dialog' }, ...content);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  return dlg;
}

function confirmDialog({ title, text, confirmLabel, confirmIcon = 'trash', cancelLabel = 'Cancel', onConfirm }) {
  const go = h('button', { class: 'btn danger', type: 'button' }, icon(confirmIcon), confirmLabel);
  const dlg = openDialog(
    h('h2', {}, title),
    h('p', {}, text),
    h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, cancelLabel), go),
  );
  go.addEventListener('click', async () => {
    go.disabled = true;
    await onConfirm();
    dlg.close();
  });
}

function confirmDelete(onConfirm) {
  confirmDialog({
    title: 'Delete this room for everyone?',
    text: 'Every message and file is erased from the server and the links stop working. Nobody, including you, can get it back.',
    confirmLabel: 'Delete forever',
    onConfirm,
  });
}

/* --------------------------------------------------------------------- chat */

function startChat({ roomId, key, auth, hostToken, nick, password, justCreated }) {
  document.title = 'Encrypted room · CipherRoom';
  const uid = randomToken(6);
  saveNick(roomId, nick);
  const guest = loadGuest(roomId);
  const st = {
    ws: null,
    ready: false,
    everReady: false,
    ended: false,
    isHost: false,
    retry: 0,
    queue: Promise.resolve(),
    unread: 0,
    last: null,
    online: 1,
    me: null,
    seq: 0,
    replyTo: null, // { i, n, q }: the message being answered
    msgs: new Map(), // server message id -> { el, name, text } for quotes and jumps
    typers: new Map(), // sender id -> { name, timer }
    typingSent: 0,
    shown: new Set(),
    peers: new Map(), // connection id -> { name, host }
    integrity: new IntegrityTracker(),
    tickets: [],
    renderTickets: null,
    knocks: new Map(),
    uploads: new Map(),
    downloads: new Map(),
    blobs: new Map(),
    busy: false,
    hostAway: false,
    hello: null,
    ticket: guest?.ticket ?? null,
    session: guest?.session ?? null,
    shownInvite: false,
  };

  const list = h('div', { class: 'messages', role: 'log', 'aria-live': 'polite' });
  const banner = h('div', { class: 'banner', hidden: true });
  const knocksBox = h('div', { class: 'knocks' });
  const online = h('span', {}, '1');
  const pill = h('span', { class: 'pill', title: 'People online' }, icon('users'), online);
  const hostSlot = h('span', { class: 'row' });
  const input = h('textarea', { rows: 1, maxlength: String(MAX_TEXT), placeholder: 'Write a message', 'aria-label': 'Message', disabled: true });
  const fileInput = h('input', { type: 'file', hidden: true });
  const attachBtn = h('button', { class: 'btn icon-only', type: 'button', title: 'Send a photo or file (up to 10 MB)', 'aria-label': 'Send a photo or file', disabled: true }, icon('clip'));
  const sendBtn = h('button', { class: 'btn primary icon-only', type: 'submit', title: 'Send', 'aria-label': 'Send', disabled: true }, icon('send'));

  const header = h(
    'header',
    { class: 'topbar' },
    h('div', { class: 'brand small' }, icon('lock'), h('span', {}, 'Encrypted room')),
    pill,
    h('div', { class: 'spacer' }),
    hostSlot,
    h('button', { class: 'btn', type: 'button', onclick: leave }, icon('logout'), 'Leave'),
  );
  const composer = h('form', { class: 'composer', onsubmit: (e) => { e.preventDefault(); sendMessage(); } }, attachBtn, fileInput, input, sendBtn);
  const typingLine = h('div', { class: 'typing', 'aria-live': 'polite' });
  const replyBar = h('div', { class: 'replybar', hidden: true });
  const chat = h('div', { class: 'chat' }, header, banner, knocksBox, list, typingLine, replyBar, composer);

  const showChat = () => app.replaceChildren(chat);
  showChat();

  /* ---- small helpers ---- */

  function setBanner(text) {
    banner.hidden = !text;
    banner.textContent = text || '';
  }
  function refreshBanner() {
    if (!st.ready) setBanner(st.everReady ? 'Connection lost. Reconnecting…' : 'Connecting…');
    else if (st.hostAway) setBanner('The host disconnected. The room ends in about a minute unless they come back.');
    else setBanner('');
  }
  function setEnabled(on) {
    input.disabled = !on;
    sendBtn.disabled = !on;
    attachBtn.disabled = !on;
  }
  const nearBottom = () => list.scrollHeight - list.scrollTop - list.clientHeight < 140;
  function sys(text, warn = false) {
    const stick = nearBottom();
    list.append(h('div', { class: `sys${warn ? ' warn' : ''}` }, text));
    if (stick) list.scrollTop = list.scrollHeight;
  }
  function updateOnline() {
    online.textContent = String(st.online);
    pill.title = [...st.peers.values()].map((p) => p.name + (p.host ? ' (host)' : '')).join(', ') || 'People online';
  }
  async function setPeer(c, hello, host) {
    const p = hello ? await decryptMessage(key, roomId, hello, 'hello') : null;
    const name = p ? String(p.n).slice(0, 24) : 'Someone';
    st.peers.set(c, { name, host: !!host });
    return name;
  }
  const send = (obj) => st.ws.send(JSON.stringify(obj));

  function endRoom(title, text) {
    st.ended = true;
    try { st.ws?.close(); } catch { /* ignore */ }
    dropToken(roomId);
    dropGuest(roomId);
    noticeCard(title, text);
  }

  /* ---- leaving ---- */

  function doLeave() {
    st.ended = true;
    try { st.ws.send(JSON.stringify({ t: 'leave' })); } catch { /* ignore */ }
    dropGuest(roomId);
    setTimeout(() => location.assign('/'), 200); // lets the "leave" message go out first
  }

  function leave() {
    if (!st.ready) return doLeave();
    confirmDialog({
      title: st.isHost ? 'Leave and end this room?' : 'Leave this room?',
      text: st.isHost
        ? 'You are the host, so leaving ends the room for everyone. All messages and files are erased.'
        : 'If you leave, this link will not let you straight back in. You will need the host to let you in again.',
      confirmLabel: st.isHost ? 'Leave and end room' : 'Leave',
      confirmIcon: 'logout',
      onConfirm: async () => doLeave(),
    });
  }

  function showWaiting() {
    document.title = 'Waiting · CipherRoom';
    app.replaceChildren(
      h(
        'main',
        { class: 'page' },
        brand(),
        h(
          'section',
          { class: 'card center' },
          h('h1', {}, 'Waiting for the host'),
          h('p', { class: 'lead' }, 'The host has to let you back in. Keep this page open.'),
          h('button', { class: 'btn', type: 'button', onclick: doLeave }, 'Cancel'),
        ),
      ),
    );
  }

  /* ---- host tools: invite links, permission requests ---- */

  function openInvite() {
    const links = h('div', { class: 'link-list' });
    const make = h('button', { class: 'btn primary', type: 'button', onclick: () => st.ready && send({ t: 'newticket' }) }, icon('userplus'), 'Create one-time link');
    const dlg = openDialog(
      h('h2', {}, 'Invite people'),
      h('p', {}, 'Make one link per person. Each link works once: after that person leaves they need your permission to come back. Send the link and the password in different messages.'),
      h('div', { class: 'field' }, h('label', {}, 'Password'), h('div', { class: 'row tight' }, h('input', { value: password, readOnly: true, class: 'mono' }), copyButton(() => password))),
      links,
      make,
      h('p', { class: 'hint' }, 'The room is erased when you leave. The password is not stored anywhere and cannot be recovered.'),
      h('div', { class: 'row end' }, h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Done')),
    );
    st.renderTickets = () => {
      links.replaceChildren(
        ...st.tickets.map((id, i) => {
          const url = `${location.origin}/r/${roomId}#${id}`;
          return h('div', { class: 'field' }, h('label', {}, `Link ${i + 1}`), h('div', { class: 'row tight' }, h('input', { value: url, readOnly: true, class: 'mono' }), copyButton(() => url)));
        }),
      );
    };
    dlg.addEventListener('close', () => { st.renderTickets = null; });
    st.renderTickets();
    if (!st.tickets.length && st.ready) send({ t: 'newticket' });
  }

  async function addKnock(c, hello) {
    if (st.knocks.has(c)) return;
    const p = hello ? await decryptMessage(key, roomId, hello, 'hello') : null;
    const name = p ? String(p.n).slice(0, 24) : 'Someone';
    const row = h(
      'div',
      { class: 'knock' },
      h('span', {}, `${name} wants to come back in`),
      h('button', { class: 'btn primary small', type: 'button', onclick: () => send({ t: 'admit', c }) }, 'Let in'),
      h('button', { class: 'btn small', type: 'button', onclick: () => send({ t: 'deny', c }) }, 'Deny'),
    );
    st.knocks.set(c, row);
    knocksBox.append(row);
  }
  function removeKnock(c) {
    st.knocks.get(c)?.remove();
    st.knocks.delete(c);
  }

  function setHostControls() {
    hostSlot.replaceChildren(
      ...(st.isHost
        ? [
            h('button', { class: 'btn', type: 'button', onclick: openInvite }, icon('userplus'), 'Invite'),
            h('button', { class: 'btn danger', type: 'button', onclick: () => confirmDelete(async () => send({ t: 'delete' })) }, icon('trash'), 'Delete room'),
          ]
        : []),
    );
  }

  /* ---- messages ---- */

  async function sendMessage() {
    const text = input.value.trim();
    if (!text || !st.ready) return;
    const body = { n: nick, u: uid, t: text, s: ++st.seq };
    if (st.replyTo) body.r = { i: st.replyTo.i, n: st.replyTo.n, q: st.replyTo.q };
    const sealed = await encryptMessage(key, roomId, body);
    send({ t: 'msg', ...sealed });
    input.value = '';
    st.typingSent = 0;
    clearReply();
    autosize();
  }

  /* ---- replies ---- */

  // A short, one-line description of a message for quoting.
  function excerpt(p) {
    const raw = p.k === 'file' ? `${IMAGE_TYPES.has(p.type) ? 'Photo' : 'File'}: ${safeName(p.name)}` : String(p.t ?? '');
    const flat = raw.replace(/\s+/g, ' ').trim();
    return flat.length > QUOTE_MAX ? `${flat.slice(0, QUOTE_MAX)}…` : flat;
  }

  function clearReply() {
    st.replyTo = null;
    replyBar.hidden = true;
    replyBar.replaceChildren();
  }

  function startReply(id) {
    const m = st.msgs.get(id);
    if (!m || !st.ready) return;
    st.replyTo = { i: id, n: m.name, q: m.text };
    replyBar.replaceChildren(
      h('div', { class: 'replybar-text' }, h('strong', {}, `Replying to ${m.name}`), h('span', {}, m.text)),
      h('button', { class: 'btn icon-only small', type: 'button', title: 'Cancel reply', 'aria-label': 'Cancel reply', onclick: clearReply }, icon('x')),
    );
    replyBar.hidden = false;
    input.focus();
  }

  function jumpTo(id) {
    const m = st.msgs.get(id);
    if (!m) return;
    m.el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    m.el.classList.add('flash');
    setTimeout(() => m.el.classList.remove('flash'), 1600);
  }

  // The quote shown above a reply. If we still hold the original, its own text is
  // shown, so a sender cannot make a reply quote words nobody said.
  function quoteBlock(r) {
    if (!r || !Number.isInteger(r.i)) return null;
    const local = st.msgs.get(r.i);
    const name = local ? local.name : String(r.n ?? 'Someone').slice(0, 24);
    const text = local ? local.text : String(r.q ?? '').slice(0, QUOTE_MAX);
    const q = h('button', { class: 'quote', type: 'button', title: local ? 'Go to the original message' : 'The original message is no longer shown', onclick: () => jumpTo(r.i) }, h('strong', {}, name), h('span', {}, text));
    if (!local) q.disabled = true;
    return q;
  }

  /* ---- typing indicator ---- */

  function renderTyping() {
    const names = [...st.typers.values()].map((t) => t.name);
    typingLine.textContent =
      names.length === 0 ? '' : names.length === 1 ? `${names[0]} is typing…` : names.length === 2 ? `${names[0]} and ${names[1]} are typing…` : 'Several people are typing…';
  }
  function clearTyper(u) {
    const t = st.typers.get(u);
    if (!t) return;
    clearTimeout(t.timer);
    st.typers.delete(u);
    renderTyping();
  }
  function clearTypers() {
    for (const t of st.typers.values()) clearTimeout(t.timer);
    st.typers.clear();
    renderTyping();
  }
  async function onTyping(m) {
    const p = await decryptMessage(key, roomId, m, 'typing');
    if (!p || typeof p.u !== 'string' || p.u === uid) return;
    const prev = st.typers.get(p.u);
    if (!prev && st.typers.size >= MAX_TYPERS) return;
    clearTimeout(prev?.timer);
    st.typers.set(p.u, { name: String(p.n).slice(0, 24), timer: setTimeout(() => clearTyper(p.u), TYPING_SHOW_MS) });
    renderTyping();
  }
  function noteTyping() {
    const now = Date.now();
    if (!st.ready || !input.value.trim() || now - st.typingSent < TYPING_GAP_MS) return;
    st.typingSent = now;
    encryptMessage(key, roomId, { n: nick, u: uid }, 'typing')
      .then((sealed) => { if (st.ready) send({ t: 'typing', ...sealed }); })
      .catch(() => { /* a missed "typing" is harmless */ });
  }
  input.addEventListener('input', noteTyping);

  function autosize() {
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 140)}px`;
  }
  input.addEventListener('input', autosize);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      sendMessage();
    }
  });

  const validFile = (p) =>
    p && p.k === 'file' && typeof p.fid === 'string' && /^[A-Za-z0-9_-]{16}$/.test(p.fid) && Number.isInteger(p.chunks) && p.chunks >= 1 &&
    p.chunks <= 170 && Number.isInteger(p.size) && p.size >= 0 && p.size <= MAX_FILE_BYTES;

  function fileBubble(p) {
    const name = safeName(p.name);
    const isImage = IMAGE_TYPES.has(p.type);
    const status = h('div', { class: 'hint' }, formatSize(p.size));
    const preview = h('div', {});
    const box = h(
      'div',
      { class: 'bubble file' },
      h('div', { class: 'file-info' }, icon('file'), h('div', {}, h('div', { class: 'file-name' }, name), status)),
      preview,
    );

    const progress = (f) => { status.textContent = `${formatSize(p.size)} · ${Math.round(f * 100)}%`; };
    const fail = (e) => { status.textContent = `${formatSize(p.size)} · ${e.message}`; };

    const action = h('button', { class: 'btn small', type: 'button' }, icon(isImage ? 'eye' : 'download'), isImage ? 'Show photo' : 'Download');
    async function run() {
      action.disabled = true;
      try {
        const blob = await fetchFile(p, progress);
        status.textContent = formatSize(p.size);
        if (isImage) {
          const img = h('img', { class: 'photo', alt: name, src: URL.createObjectURL(blob) });
          preview.replaceChildren(img);
          action.remove();
        } else {
          const a = h('a', { href: URL.createObjectURL(blob), download: name });
          document.body.append(a);
          a.click();
          a.remove();
          action.disabled = false;
        }
      } catch (e) {
        fail(e);
        action.disabled = false;
      }
    }
    action.addEventListener('click', run);
    box.append(action);
    if (isImage && (p.size <= AUTO_SHOW_IMAGE_BYTES || st.blobs.has(p.fid))) run();
    return box;
  }

  async function addMessage(env, live) {
    if (st.shown.has(env.id)) return;
    st.shown.add(env.id);

    const idCheck = st.integrity.checkId(env.id);
    if (idCheck === 'replay') return sys('The server repeated an old message. It was ignored.', true);
    if (idCheck === 'gap') sys('Some messages may be missing: the server skipped part of the conversation.', true);

    const p = await decryptMessage(key, roomId, env);
    if (p) {
      const seq = st.integrity.checkSeq(p.u, p.s);
      if (seq === 'duplicate') return sys('A repeated message was ignored.', true);
      if (seq === 'gap') sys(`Some messages from ${String(p.n).slice(0, 24)} may be missing.`, true);
    }

    const when = new Date(env.ts);
    const day = when.toDateString();
    const stick = nearBottom();

    if (st.last?.day !== day) {
      list.append(h('div', { class: 'day' }, when.toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long' })));
    }
    const mine = !!p && p.u === uid;
    const sender = p ? String(p.u) : '?';
    const cont = st.last && st.last.sender === sender && st.last.day === day && env.ts - st.last.ts < 120_000;
    st.last = { sender, day, ts: env.ts };

    const el = h('div', { class: `msg ${mine ? 'mine' : 'theirs'}${cont ? ' cont' : ''}` });
    if (!cont) {
      const name = h('span', { class: 'name' }, p ? String(p.n).slice(0, 24) : 'Unknown');
      if (p && !mine) {
        let hue = 0;
        for (const ch of String(p.n)) hue = (hue * 31 + ch.charCodeAt(0)) % 360;
        name.style.setProperty('--hue', String(hue));
      }
      el.append(h('div', { class: 'meta' }, name, h('time', {}, when.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))));
    }
    let bubble;
    if (!p) bubble = h('div', { class: 'bubble bad' }, 'This message could not be decrypted.');
    else if (p.k === 'file') bubble = validFile(p) ? fileBubble(p) : h('div', { class: 'bubble bad' }, 'This file message is not valid.');
    else {
      bubble = h('div', { class: 'bubble' });
      const quote = p.r ? quoteBlock(p.r) : null;
      if (quote) bubble.append(quote);
      bubble.append(document.createTextNode(String(p.t ?? '')));
    }
    const usable = !!p && (p.k === 'file' ? validFile(p) : true);
    if (usable) {
      const name = String(p.n).slice(0, 24);
      st.msgs.set(env.id, { el, name, text: excerpt(p) });
      const replyBtn = h('button', { class: 'reply-btn', type: 'button', title: 'Reply', 'aria-label': `Reply to ${name}`, onclick: () => startReply(env.id) }, icon('reply'));
      el.append(h('div', { class: 'line' }, bubble, replyBtn));
    } else {
      el.append(bubble);
    }
    if (p && typeof p.u === 'string') clearTyper(p.u);
    list.append(el);

    if (stick || mine || !live) list.scrollTop = list.scrollHeight;
    if (live && !mine && document.hidden) {
      st.unread += 1;
      document.title = `(${st.unread}) Encrypted room · CipherRoom`;
    }
  }
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      st.unread = 0;
      document.title = 'Encrypted room · CipherRoom';
    }
  });

  /* ---- files ---- */

  async function shrinkImage(file) {
    // Re-encoding also strips hidden data such as GPS location from photos.
    try {
      const bmp = await createImageBitmap(file);
      const scale = Math.min(1, 1920 / Math.max(bmp.width, bmp.height));
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.round(bmp.width * scale));
      canvas.height = Math.max(1, Math.round(bmp.height * scale));
      canvas.getContext('2d').drawImage(bmp, 0, 0, canvas.width, canvas.height);
      bmp.close?.();
      return await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.85));
    } catch {
      return null;
    }
  }

  async function sendFile(file) {
    if (!st.ready) return;
    if (st.busy) return sys('Wait for the current file to finish sending.', true);
    st.busy = true;
    const note = h('div', { class: 'sys' }, `Preparing ${safeName(file.name)}…`);
    list.append(note);
    list.scrollTop = list.scrollHeight;
    try {
      let blob = file;
      let name = safeName(file.name);
      let type = file.type || 'application/octet-stream';
      if (IMAGE_TYPES.has(type) && type !== 'image/gif') {
        const small = await shrinkImage(file);
        if (small) {
          blob = small;
          type = 'image/jpeg';
          name = `${name.replace(/\.[^.]+$/, '')}.jpg`;
        }
      }
      if (blob.size === 0) throw new Error('That file is empty.');
      if (blob.size > MAX_FILE_BYTES) throw new Error(`${name} is larger than 10 MB.`);

      const bytes = new Uint8Array(await blob.arrayBuffer());
      const n = Math.ceil(bytes.length / CHUNK_SIZE);
      const fid = randomToken(12);

      const up = { acked: 0, sent: 0, done: false, fail: null, wake: null };
      st.uploads.set(fid, {
        ack: () => { up.acked += 1; up.wake?.(); },
        done: () => { up.done = true; up.wake?.(); },
        failWith: (err) => { up.fail = err; up.wake?.(); },
      });
      const waitFor = (cond) => new Promise((resolve) => {
        const check = () => {
          if (up.fail || cond()) { up.wake = null; resolve(); } else up.wake = check;
        };
        check();
      });

      try {
        for (let i = 0; i < n; i++) {
          await waitFor(() => up.sent - up.acked < 6); // keep only a few chunks in flight
          if (up.fail) throw up.fail;
          const sealed = await encryptChunk(key, roomId, fid, i, n, bytes.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE));
          send({ t: 'fchunk', f: fid, i, n, ...sealed });
          up.sent += 1;
          note.textContent = `Sending ${name}… ${Math.round(((i + 1) / n) * 100)}%`;
        }
        await waitFor(() => up.done);
        if (up.fail) throw up.fail;
      } finally {
        st.uploads.delete(fid);
      }

      st.blobs.set(fid, new Blob([bytes], { type: IMAGE_TYPES.has(type) ? type : 'application/octet-stream' }));
      const sealed = await encryptMessage(key, roomId, { k: 'file', n: nick, u: uid, s: ++st.seq, fid, name, type, size: bytes.length, chunks: n });
      send({ t: 'msg', ...sealed });
    } catch (e) {
      sys(e.message || 'Could not send the file.', true);
    } finally {
      note.remove();
      st.busy = false;
    }
  }

  async function fetchFile(meta, onProgress) {
    const cached = st.blobs.get(meta.fid);
    if (cached) return cached;
    if (!st.ready) throw new Error('Not connected.');
    if (st.downloads.has(meta.fid)) throw new Error('Already downloading.');
    const parts = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        st.downloads.delete(meta.fid);
        reject(new Error('Timed out.'));
      }, 120_000);
      st.downloads.set(meta.fid, {
        n: meta.chunks,
        chunks: new Array(meta.chunks),
        got: 0,
        onProgress,
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      send({ t: 'fget', f: meta.fid });
    });
    const blob = new Blob(parts, { type: IMAGE_TYPES.has(meta.type) ? meta.type : 'application/octet-stream' });
    if (blob.size !== meta.size) throw new Error('The file is incomplete or was changed.');
    st.blobs.set(meta.fid, blob);
    return blob;
  }

  async function onFileChunk(m) {
    const d = st.downloads.get(m.f);
    if (!d || m.n !== d.n || !Number.isInteger(m.i) || m.i < 0 || m.i >= d.n || d.chunks[m.i]) return;
    const bytes = await decryptChunk(key, roomId, m.f, m.i, m.n, { iv: m.iv, ct: m.ct });
    if (!bytes) {
      st.downloads.delete(m.f);
      return d.reject(new Error('The file could not be verified.'));
    }
    d.chunks[m.i] = bytes;
    d.got += 1;
    d.onProgress?.(d.got / d.n);
    if (d.got === d.n) {
      st.downloads.delete(m.f);
      d.resolve(d.chunks);
    }
  }

  attachBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    const f = fileInput.files?.[0];
    fileInput.value = '';
    if (f) sendFile(f);
  });

  /* ---- server events ---- */

  async function onServer(m) {
    switch (m.t) {
      case 'ready': {
        st.ready = true;
        st.everReady = true;
        st.retry = 0;
        st.me = m.you;
        st.isHost = !!m.isHost;
        st.online = m.online;
        st.hostAway = !!m.hostAway;
        if (m.session) {
          st.session = m.session;
          saveGuest(roomId, { ticket: st.ticket, session: st.session });
        }
        st.peers.clear();
        for (const p of m.peers) await setPeer(p.c, p.hello, p.h);
        st.peers.set(m.you, { name: nick, host: st.isHost });
        updateOnline();
        showChat();
        refreshBanner();
        setHostControls();
        setEnabled(true);

        list.replaceChildren();
        st.msgs.clear();
        clearTypers();
        clearReply();
        st.shown.clear();
        st.last = null;
        st.integrity = new IntegrityTracker();
        for (const env of m.history) await addMessage(env, false);
        list.scrollTop = list.scrollHeight;
        for (const k of m.knocks ?? []) await addKnock(k.c, k.hello);
        input.focus();
        if (justCreated && st.isHost && !st.shownInvite) {
          st.shownInvite = true;
          openInvite();
        }
        break;
      }
      case 'msg':
        await addMessage(m.m, true);
        break;
      case 'typing':
        await onTyping(m);
        break;
      case 'joined': {
        if (m.replaces) st.peers.delete(m.replaces);
        const name = await setPeer(m.c, m.hello, m.host);
        st.online = m.online;
        updateOnline();
        sys(m.back ? `${name} reconnected` : `${name} joined`);
        if (m.host) {
          st.hostAway = false;
          refreshBanner();
        }
        break;
      }
      case 'left': {
        const p = st.peers.get(m.c);
        st.peers.delete(m.c);
        st.online = m.online;
        updateOnline();
        sys(`${p?.name ?? 'Someone'} left`);
        break;
      }
      case 'host_away':
        st.hostAway = true;
        refreshBanner();
        break;
      case 'pending':
        showWaiting();
        break;
      case 'knock':
        await addKnock(m.c, m.hello);
        break;
      case 'knock_done':
        removeKnock(m.c);
        break;
      case 'ticket':
        st.tickets.push(m.id);
        st.renderTickets?.();
        break;
      case 'denied':
        st.ended = true;
        try { st.ws?.close(); } catch { /* ignore */ }
        noticeCard('The host did not let you in', 'Ask the host if you should try again.', 'Try again', () => location.reload());
        break;
      case 'deleted':
        if (m.reason === 'host_left') endRoom('The host left', 'The host left, so this room has ended. Its messages and files are erased and the link no longer works.');
        else endRoom('This room was deleted', 'The host permanently erased it. Nothing is left on the server and the links no longer work.');
        break;
      case 'fack':
        st.uploads.get(m.f)?.ack();
        break;
      case 'fdone':
        st.uploads.get(m.f)?.done();
        break;
      case 'fchunk':
        await onFileChunk(m);
        break;
      case 'fmissing': {
        const d = st.downloads.get(m.f);
        if (d) {
          st.downloads.delete(m.f);
          d.reject(new Error('The file is no longer available.'));
        }
        break;
      }
      case 'error': {
        if (m.code === 'not_found') return endRoom('This room has ended', 'The host left or deleted it, so the room and its messages are erased. Ask for a new link.');
        if (!st.everReady) {
          st.ended = true;
          try { st.ws?.close(); } catch { /* ignore */ }
          if (m.code === 'bad_credentials' || m.code === 'rate_limited') return showJoin(roomId, { error: ERRORS[m.code], nickValue: nick });
          return noticeCard('Could not join', ERRORS[m.code] || 'Something went wrong.');
        }
        if (m.code === 'replaced') return endRoom('Disconnected', ERRORS.replaced);
        if (m.code === 'storage_full') {
          st.uploads.get(m.f)?.failWith(new Error('The room file storage is full (50 MB). Nothing was sent.'));
        } else if (m.code === 'bad_file') {
          st.uploads.get(m.f)?.failWith(new Error('The server refused that file.'));
        } else if (m.code === 'rate_limited') {
          setBanner('You are sending too fast. Slow down a little.');
        } else if (m.code === 'too_many_invites') {
          sys('You have reached the limit of invite links for this room.', true);
        } else if (m.code === 'room_full') {
          sys('The room is full, so that person could not be let in.', true);
        }
        break;
      }
      default:
        break;
    }
  }

  function connect() {
    if (st.ended) return;
    refreshBanner();
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
    st.ws = ws;
    ws.onopen = async () => {
      try {
        st.hello ??= await encryptMessage(key, roomId, { n: nick, u: uid }, 'hello');
        ws.send(JSON.stringify({ t: 'join', room: roomId, auth, hostToken, ticket: st.ticket, session: st.session, hello: st.hello }));
      } catch {
        /* connection closed meanwhile */
      }
    };
    ws.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      st.queue = st.queue.then(() => onServer(m)).catch(() => {});
    };
    ws.onclose = () => {
      if (st.ended) return;
      st.ready = false;
      setEnabled(false);
      const lost = new Error('Connection lost.');
      for (const u of st.uploads.values()) u.failWith(lost);
      for (const [f, d] of st.downloads) {
        st.downloads.delete(f);
        d.reject(lost);
      }
      refreshBanner();
      setTimeout(connect, Math.min(1000 * 2 ** st.retry++, 15000));
    };
  }

  connect();
}

/* -------------------------------------------------------------------- boot */

if ('serviceWorker' in navigator && window.isSecureContext) {
  navigator.serviceWorker.register('/sw.js').catch(() => {}); // only makes the app installable
}

if (!window.isSecureContext || !globalThis.crypto?.subtle) {
  showUnsupported();
} else {
  const m = location.pathname.match(/^\/r\/([A-Za-z0-9_-]{22})\/?$/);
  if (m) {
    // The personal ticket lives in the #fragment, so it never reaches the server in a request.
    const frag = location.hash.slice(1);
    if (TICKET_RE.test(frag)) {
      const prev = loadGuest(m[1]);
      saveGuest(m[1], { ticket: frag, session: prev?.ticket === frag ? prev.session : null });
      history.replaceState(null, '', location.pathname);
    }
    showJoin(m[1]);
  } else {
    showHome();
  }
}
