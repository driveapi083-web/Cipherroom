// Detects a server (or anyone in the middle) repeating, reordering or silently
// dropping messages. Pure logic, shared with the test-suite.
//
// Two independent checks:
//  - checkId:  the server numbers messages 1, 2, 3 ... in order.
//  - checkSeq: every sender counts its own messages inside the encrypted payload,
//              which the server can neither read nor forge.

export class IntegrityTracker {
  constructor() {
    this.lastId = null;
    this.lastSeq = new Map(); // sender id -> last sequence number seen
  }

  /** @returns {'ok'|'gap'|'replay'} */
  checkId(id) {
    if (!Number.isInteger(id)) return 'replay';
    if (this.lastId === null) {
      this.lastId = id;
      return 'ok';
    }
    if (id <= this.lastId) return 'replay';
    const gap = id !== this.lastId + 1;
    this.lastId = id;
    return gap ? 'gap' : 'ok';
  }

  /** @returns {'ok'|'gap'|'duplicate'|'invalid'} */
  checkSeq(sender, seq) {
    if (typeof sender !== 'string' || !Number.isInteger(seq) || seq < 1) return 'invalid';
    const last = this.lastSeq.get(sender);
    if (last === undefined) {
      this.lastSeq.set(sender, seq); // first message we see from them sets the baseline
      return 'ok';
    }
    if (seq <= last) return 'duplicate';
    this.lastSeq.set(sender, seq);
    return seq === last + 1 ? 'ok' : 'gap';
  }
}
