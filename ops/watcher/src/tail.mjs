/**
 * tail — incremental, rotation-safe reader over the `bot.audit.v1` JSONL streams.
 *
 * The watcher is a *read-only* consumer of `/var/log/dshbot` (t3 §3 mounts it `:ro`), so
 * it cannot use a file descriptor that survives a rename; `bot-audit` rotates by
 * rename+create (F3 append-only discipline), which means the reader must notice that the
 * inode/path shrank and restart from zero. Byte offsets are persisted so a restart of the
 * watcher does not re-read the whole history and re-fire every old finding.
 *
 * A line that fails to parse is counted, not thrown: one hostile or truncated line must
 * not stop detection (fail-open on parsing, fail-closed on detection).
 */

import { openSync, readSync, closeSync, fstatSync, existsSync } from 'node:fs';

const MAX_BYTES_PER_FILE = 512 * 1024; // one tick can never swallow more than this per stream
const MAX_LINE_BYTES = 256 * 1024;

export class JsonlTailer {
  /**
   * @param {{paths: string[], offsets?: Record<string, number>, maxBytesPerFile?: number}} opts
   */
  constructor(opts) {
    this.paths = opts.paths;
    this.offsets = { ...(opts.offsets || {}) };
    this.badLines = 0;
    this.maxBytes = opts.maxBytesPerFile ?? MAX_BYTES_PER_FILE;
  }

  snapshot() {
    return { ...this.offsets };
  }

  /** Read everything appended since the last call. @returns {object[]} */
  read() {
    const out = [];
    for (const path of this.paths) {
      if (!existsSync(path)) continue;
      let fd;
      try {
        fd = openSync(path, 'r');
        const { size } = fstatSync(fd);
        // Rotation or truncation: the recorded offset is now beyond the file.
        // A path with no recorded offset starts at 0. Bootstrapping to end-of-file is a
        // policy of the loop (index.mjs), not of the reader: on a cold start the watcher
        // must not re-fire every historical finding, and that has to be an explicit seek.
        const from = this.offsets[path] ?? 0;
        const start = from > size ? 0 : from;
        const want = Math.min(size - start, this.maxBytes);
        if (want <= 0) {
          this.offsets[path] = size;
          continue;
        }
        const buf = Buffer.alloc(want);
        const got = readSync(fd, buf, 0, want, start);
        let consumed = 0;
        const text = buf.slice(0, got);
        for (;;) {
          const nl = text.indexOf(0x0a, consumed);
          if (nl < 0) break;
          const lineBytes = text.slice(consumed, nl);
          consumed = nl + 1;
          const record = this.#parse(lineBytes);
          if (record) out.push(record);
        }
        // Only *complete* lines advance the cursor: a partial trailing line is re-read on
        // the next tick, by which time the writer has finished it. The exception is the
        // runaway-line guard below, which gives up on a remainder that is too large to be
        // one audit record, so a single pathological line cannot wedge detection forever.
        this.offsets[path] = start + consumed;
        if (text.length - consumed > MAX_LINE_BYTES) this.offsets[path] = start + got;
      } catch (err) {
        // Unreadable stream: keep the previous offset, report once per path per tick.
        this.readError = String(err.code || err.message).slice(0, 40);
      } finally {
        if (fd !== undefined) closeSync(fd);
      }
    }
    return out;
  }

  #parse(lineBytes) {
    if (lineBytes.length === 0) return null;
    try {
      const parsed = JSON.parse(lineBytes.toString('utf8'));
      if (!parsed || typeof parsed !== 'object' || typeof parsed.type !== 'string') return null;
      return parsed;
    } catch {
      this.badLines += 1;
      return null;
    }
  }
}
