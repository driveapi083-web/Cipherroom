// Minimal, dependency-free WebSocket server side (RFC 6455).
//
// Deliberately small: text messages only, no extensions, no sub-protocols.
// Clients MUST mask frames (as the RFC requires); unmasked frames are rejected.

import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const OP = { CONT: 0x0, TEXT: 0x1, BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };
const MAX_WRITE_BACKLOG = 8 * 1024 * 1024; // drop clients that can't keep up

export const READY = { OPEN: 1, CLOSING: 2, CLOSED: 3 };

const utf8 = new TextDecoder('utf-8', { fatal: true });

function frame(opcode, payload) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  header[0] = 0x80 | opcode; // FIN + opcode, server frames are never masked
  return Buffer.concat([header, payload]);
}

function validCloseCode(c) {
  return (c >= 1000 && c <= 1003) || (c >= 1007 && c <= 1011) || (c >= 3000 && c <= 4999);
}

export class WebSocketConnection extends EventEmitter {
  constructor(socket, { maxPayload = 32 * 1024 } = {}) {
    super();
    this.socket = socket;
    this.maxPayload = maxPayload;
    this.readyState = READY.OPEN;
    this.buf = Buffer.alloc(0);
    this.fragOpcode = 0;
    this.fragChunks = [];
    this.fragSize = 0;
    this.closeTimer = null;

    socket.setNoDelay(true);
    socket.setTimeout(0);
    socket.on('data', (chunk) => this.#onData(chunk));
    socket.on('error', () => socket.destroy());
    socket.on('close', () => {
      clearTimeout(this.closeTimer);
      if (this.readyState !== READY.CLOSED) {
        this.readyState = READY.CLOSED;
        this.emit('close');
      }
    });
  }

  /** Send a text message. Silently ignored unless the connection is open. */
  send(text) {
    if (this.readyState !== READY.OPEN) return;
    if (this.socket.writableLength > MAX_WRITE_BACKLOG) {
      this.terminate();
      return;
    }
    this.socket.write(frame(OP.TEXT, Buffer.from(text, 'utf8')));
  }

  ping() {
    if (this.readyState === READY.OPEN) this.socket.write(frame(OP.PING, Buffer.alloc(0)));
  }

  /** Start the closing handshake. */
  close(code = 1000, reason = '') {
    if (this.readyState !== READY.OPEN) return;
    this.readyState = READY.CLOSING;
    const r = Buffer.from(reason, 'utf8').subarray(0, 123);
    const payload = Buffer.alloc(2 + r.length);
    payload.writeUInt16BE(code, 0);
    r.copy(payload, 2);
    this.socket.write(frame(OP.CLOSE, payload));
    // If the peer never answers, drop the TCP connection.
    this.closeTimer = setTimeout(() => this.socket.destroy(), 3000);
    this.closeTimer.unref();
  }

  /** Drop the connection immediately. */
  terminate() {
    this.socket.destroy();
  }

  #fail(code) {
    // Protocol violation: tell the peer and hang up.
    if (this.readyState === READY.OPEN) this.close(code);
    this.buf = Buffer.alloc(0);
    this.socket.destroy();
  }

  #onData(chunk) {
    if (this.readyState === READY.CLOSED) return;
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;

    for (;;) {
      const buf = this.buf;
      if (buf.length < 2) return;

      const fin = (buf[0] & 0x80) !== 0;
      const rsv = buf[0] & 0x70;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let offset = 2;

      if (rsv !== 0) return this.#fail(1002); // no extensions negotiated
      if (!masked) return this.#fail(1002); // clients must mask

      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        const big = buf.readBigUInt64BE(2);
        if (big > BigInt(this.maxPayload)) return this.#fail(1009);
        len = Number(big);
        offset = 10;
      }
      if (len > this.maxPayload) return this.#fail(1009); // checked before buffering the body

      const isControl = opcode >= 0x8;
      if (isControl && (!fin || len > 125)) return this.#fail(1002);

      if (buf.length < offset + 4 + len) return; // wait for the rest of the frame

      const mask = buf.subarray(offset, offset + 4);
      const payload = Buffer.from(buf.subarray(offset + 4, offset + 4 + len)); // copy, then unmask in place
      for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
      this.buf = buf.subarray(offset + 4 + len);

      if (!this.#onFrame(fin, opcode, payload)) return;
    }
  }

  /** Returns false when the connection was torn down. */
  #onFrame(fin, opcode, payload) {
    switch (opcode) {
      case OP.CONT: {
        if (!this.fragOpcode) return this.#fail(1002), false;
        this.fragSize += payload.length;
        if (this.fragSize > this.maxPayload) return this.#fail(1009), false;
        this.fragChunks.push(payload);
        if (fin) {
          const op = this.fragOpcode;
          const whole = Buffer.concat(this.fragChunks);
          this.fragOpcode = 0;
          this.fragChunks = [];
          this.fragSize = 0;
          return this.#deliver(op, whole);
        }
        return true;
      }
      case OP.TEXT:
      case OP.BINARY: {
        if (this.fragOpcode) return this.#fail(1002), false; // new message mid-fragment
        if (fin) return this.#deliver(opcode, payload);
        this.fragOpcode = opcode;
        this.fragChunks = [payload];
        this.fragSize = payload.length;
        return true;
      }
      case OP.CLOSE: {
        let code = 1005;
        if (payload.length === 1) return this.#fail(1002), false;
        if (payload.length >= 2) {
          code = payload.readUInt16BE(0);
          if (!validCloseCode(code)) return this.#fail(1002), false;
          try {
            utf8.decode(payload.subarray(2));
          } catch {
            return this.#fail(1007), false;
          }
        }
        if (this.readyState === READY.OPEN) {
          this.readyState = READY.CLOSING;
          const echo = Buffer.alloc(2);
          echo.writeUInt16BE(code === 1005 ? 1000 : code, 0);
          this.socket.write(frame(OP.CLOSE, echo));
        }
        this.socket.end();
        return false;
      }
      case OP.PING:
        if (this.readyState === READY.OPEN) this.socket.write(frame(OP.PONG, payload));
        return true;
      case OP.PONG:
        this.emit('pong');
        return true;
      default:
        return this.#fail(1002), false;
    }
  }

  #deliver(opcode, data) {
    if (opcode === OP.BINARY) return this.#fail(1003), false; // this app only speaks text
    let text;
    try {
      text = utf8.decode(data);
    } catch {
      return this.#fail(1007), false;
    }
    if (this.readyState === READY.OPEN) this.emit('message', text);
    return true;
  }
}

/**
 * Complete the HTTP -> WebSocket upgrade. Returns a WebSocketConnection,
 * or null after replying with an HTTP error and closing the socket.
 */
export function acceptUpgrade(req, socket, head, options) {
  const reject = (status, text) => {
    socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    return null;
  };

  const key = req.headers['sec-websocket-key'];
  const upgrade = String(req.headers.upgrade || '').toLowerCase();
  const connection = String(req.headers.connection || '').toLowerCase();

  if (req.method !== 'GET') return reject(405, 'Method Not Allowed');
  if (upgrade !== 'websocket' || !connection.split(',').map((s) => s.trim()).includes('upgrade')) {
    return reject(400, 'Bad Request');
  }
  if (req.headers['sec-websocket-version'] !== '13') return reject(426, 'Upgrade Required');
  if (typeof key !== 'string' || Buffer.from(key, 'base64').length !== 16) return reject(400, 'Bad Request');

  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );

  const conn = new WebSocketConnection(socket, options);
  if (head && head.length) conn.socket.emit('data', head);
  return conn;
}
