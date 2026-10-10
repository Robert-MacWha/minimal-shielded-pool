/**
 * Files that hold secrets: wallet seeds and states, fixtures with note openings and authorizer
 * keys, and disclosure receipts. Wallet states and fixtures are written by writePrivate,
 * receipts by writeNewPrivate, both creating the file owner-only (mode 0600); seeds are only
 * read. Only readPrivate, which reads seeds and wallet states, refuses a file its group or
 * others have any permission on: fixtures and receipts are read without that check. A file
 * this module refuses is an InputError; one that changed after it was checked is a
 * FileChangedError, which each caller words for its own users.
 */
import { randomBytes } from "node:crypto";
import {
  closeSync,
  fstatSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { InputError, UserError } from "./errors.ts";
import { parse } from "./json.ts";

/** The file at a path appeared or changed after the check that writePrivate was given. */
export class FileChangedError extends UserError {}

/** Which file sits at a path: inode, modification time in nanoseconds and size. */
export interface FileIdentity {
  readonly ino: bigint;
  readonly mtimeNs: bigint;
  readonly size: bigint;
}

/** The identity of the file at path (following links), or null if nothing is there. */
export function fileIdentity(path: string): FileIdentity | null {
  const st = unlessMissing(() => statSync(path, { bigint: true }));
  return st === null ? null : { ino: st.ino, mtimeNs: st.mtimeNs, size: st.size };
}

function sameFile(a: FileIdentity | null, b: FileIdentity): boolean {
  return a !== null && a.ino === b.ino && a.mtimeNs === b.mtimeNs && a.size === b.size;
}

/**
 * Replaces path with text in a new owner-only file. The text goes to a temporary file in the
 * same directory, created exclusively with mode 0600 and synced, which is then renamed over
 * path: a reader never sees a partial file, and one holding an earlier world-readable copy
 * open never sees the new text. The directory is synced last, so that a crash after this
 * returns cannot bring the earlier file back.
 *
 * `previous` is what an earlier check saw at path. Leave it out to replace whatever is there.
 * null means path must still be absent, otherwise it must still be that same file, or the write
 * throws FileChangedError, so a concurrent run cannot write over a fixture another run just
 * created. No temporary file survives a failure.
 */
export function writePrivate(path: string, text: string, previous?: FileIdentity | null): void {
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString("hex")}`);
  const fd = openSync(temporary, "wx", 0o600);
  try {
    try {
      writeFileSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (previous === null) {
      // A hard link fails if anything, even a dangling link, appeared at path.
      try {
        linkSync(temporary, path);
      } catch (error) {
        if (errorCode(error) !== "EEXIST") throw error;
        throw new FileChangedError(`${path} appeared since it was checked`);
      }
      unlinkSync(temporary);
    } else if (previous !== undefined && !sameFile(fileIdentity(path), previous)) {
      throw new FileChangedError(`${path} changed since it was checked`);
    } else {
      renameSync(temporary, path);
    }
  } catch (error) {
    unlessMissing(() => unlinkSync(temporary));
    throw error;
  }
  const directory = openSync(dirname(path), "r");
  try {
    fsyncSync(directory);
  } finally {
    closeSync(directory);
  }
}

/**
 * The text of a file that holds secrets, refused if its group or others have any permission
 * on it. The mode is checked again on the opened file, so a file swapped in after the first
 * check is not read.
 */
export function readPrivate(path: string): string {
  refuseShared(path, statSync(path).mode);
  const fd = openSync(path, "r");
  try {
    refuseShared(path, fstatSync(fd).mode);
    return readText(path, readFileSync(fd));
  } finally {
    closeSync(fd);
  }
}

/**
 * The value of the JSON file at path, its text read by read. A file that is not UTF-8 or not
 * JSON is refused with an InputError naming the file.
 */
export function readJson(path: string, read: (path: string) => string = readText): unknown {
  const text = read(path);
  try {
    return parse(text);
  } catch (error) {
    // V8 quotes up to ten characters around an unexpected token, which can be part of a key
    // or seed held in the file. Keep only the kind of error, and the position V8 gives for
    // the other kinds.
    const message = (error as Error).message;
    const reason = message.endsWith(" is not valid JSON") ? "Unexpected token" : message;
    throw new InputError(`${path} is not JSON: ${reason}`);
  }
}

// Strict UTF-8: a lossy decode would read a damaged file as some other text. \r\n and \r read
// as \n, and a byte order mark is kept, so a JSON file that starts with one is refused.
function readText(path: string, bytes: Uint8Array = readFileSync(path)): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
      .decode(bytes)
      .replace(/\r\n?/g, "\n");
  } catch {
    throw new InputError(`${path} is not UTF-8 text`);
  }
}

function refuseShared(path: string, mode: number): void {
  if (mode & 0o077) throw new InputError(`${path} is readable by other users; chmod 600 it first`);
}

/**
 * Creates path readable only by its owner. An exclusive create refuses any existing file and
 * any link, even a dangling one, so a link planted at the path cannot redirect the write.
 */
export function writeNewPrivate(path: string, text: string): void {
  try {
    writeFileSync(path, text, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (errorCode(error) === "EEXIST") throw new InputError(`${path} exists`);
    throw error;
  }
}

/**
 * Runs body while holding the lock of a state file, so that two runs on one wallet state
 * cannot overwrite each other's changes or hand out one direct secret twice. The lock is the
 * directory `<state>.lock.d`, created atomically. A second run waits for it, up to waitMs,
 * then names the lock so that one left by a killed run can be removed. The lock is also
 * released when the process exits early, which runCli makes Ctrl-C, SIGTERM and SIGHUP do.
 */
export async function withLock<T>(
  statePath: string,
  body: () => T | Promise<T>,
  { waitMs = 60_000 } = {},
): Promise<T> {
  const lock = `${statePath}.lock.d`;
  const deadline = Date.now() + waitMs;
  for (;;) {
    try {
      mkdirSync(lock, 0o700);
      break;
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
    }
    if (Date.now() >= deadline) {
      throw new InputError(
        `${lock} is held by another run; if no other run is active, remove it and try again`,
      );
    }
    await sleep(100);
  }
  const release = () => unlessMissing(() => rmdirSync(lock));
  process.on("exit", release);
  try {
    return await body();
  } finally {
    process.off("exit", release);
    release();
  }
}

/** What f returns, or null when it fails because its path does not exist. */
function unlessMissing<T>(f: () => T): T | null {
  try {
    return f();
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  }
}

function errorCode(error: unknown): unknown {
  return error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined;
}
