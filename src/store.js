// Room storage: memory only. Nothing is ever written to disk.
//
// A room holds public metadata (salt, hashes of secrets), invite tickets,
// AES-GCM ciphertext messages and AES-GCM ciphertext file chunks. The server never
// has the room password, so it can never read any of it. When a room is deleted,
// every reference to it is dropped, and a restart of the server erases all rooms.

const MB = 1024 * 1024;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;

export const MAX_FILE_CT_BYTES = 10 * MB + 170 * 16 + 4096; // 10 MB of data plus per-chunk overhead
export const MAX_FILES_PER_ROOM = 100;

export const isValidId = (id) => typeof id === 'string' && ID_RE.test(id);

export class Store {
  constructor({ maxHistory = 2000, roomFileBytes = 50 * MB, totalFileBytes = 200 * MB } = {}) {
    this.maxHistory = maxHistory;
    this.roomFileBytes = roomFileBytes;
    this.totalFileBytes = totalFileBytes;
    this.fileBytes = 0; // across all rooms
    this.rooms = new Map(); // id -> { meta, messages, tickets, files, fileBytes }
  }

  count() {
    return this.rooms.size;
  }

  /** Metadata only. */
  readMeta(id) {
    return isValidId(id) ? (this.rooms.get(id)?.meta ?? null) : null;
  }

  /** The room with its encrypted history, or null. */
  open(id) {
    return isValidId(id) ? (this.rooms.get(id) ?? null) : null;
  }

  create(meta) {
    if (!isValidId(meta.id) || this.rooms.has(meta.id)) throw new Error('invalid or duplicate room id');
    this.rooms.set(meta.id, { meta, messages: [], tickets: new Map(), files: new Map(), fileBytes: 0 });
  }

  /** Append an encrypted message; returns the stored record. */
  append(id, { iv, ct }) {
    const room = this.open(id);
    if (!room) return null;
    const last = room.messages.length ? room.messages[room.messages.length - 1].id : 0;
    const msg = { id: last + 1, ts: Date.now(), iv, ct };
    room.messages.push(msg);
    if (room.messages.length > this.maxHistory + 200) room.messages = room.messages.slice(-this.maxHistory);
    return msg;
  }

  /**
   * Store one encrypted file chunk.
   * @returns {'ok'|'done'|'dup'|'full'|'bad'|'gone'}
   */
  putChunk(id, { f, i, n, iv, ct, owner }) {
    const room = this.open(id);
    if (!room) return 'gone';

    const size = Math.floor((ct.length * 3) / 4);
    let file = room.files.get(f);
    const created = !file;
    if (created) {
      if (room.files.size >= MAX_FILES_PER_ROOM) return 'bad';
      file = { n, chunks: new Array(n).fill(null), got: 0, bytes: 0, owner, complete: false };
      room.files.set(f, file);
    } else if (file.owner !== owner) {
      return 'bad'; // nobody else may add to (or poison) someone's upload
    }
    const reject = (code) => {
      if (created) room.files.delete(f);
      return code;
    };

    if (file.n !== n) return reject('bad');
    if (file.complete || file.chunks[i]) return 'dup';
    if (file.bytes + size > MAX_FILE_CT_BYTES) return reject('bad');
    if (room.fileBytes + size > this.roomFileBytes || this.fileBytes + size > this.totalFileBytes) return reject('full');

    file.chunks[i] = { iv, ct };
    file.got += 1;
    file.bytes += size;
    room.fileBytes += size;
    this.fileBytes += size;
    if (file.got === file.n) {
      file.complete = true;
      return 'done';
    }
    return 'ok';
  }

  getFile(id, f) {
    return this.open(id)?.files.get(f) ?? null;
  }

  /** Remove a (partial) file and give its space back. */
  dropFile(id, f) {
    const room = this.open(id);
    const file = room?.files.get(f);
    if (!file) return;
    room.files.delete(f);
    room.fileBytes -= file.bytes;
    this.fileBytes -= file.bytes;
  }

  /** Permanently erase a room and everything in it. */
  delete(id) {
    const room = this.open(id);
    if (!room) return false;
    this.fileBytes -= room.fileBytes;
    for (const t of room.tickets.values()) clearTimeout(t.timer);
    room.tickets.clear();
    for (const file of room.files.values()) file.chunks.length = 0;
    room.files.clear();
    room.messages.length = 0;
    room.messages = null;
    room.meta = null;
    this.rooms.delete(id);
    return true;
  }
}
