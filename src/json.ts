/**
 * JSON that keeps protocol integers exact. JSON.parse rounds integers above 2^53 and
 * JSON.stringify throws on bigint, while the files this repository reads and writes hold
 * 254-bit field elements and uint256 chain ids as bare numbers.
 */
import { InputError } from "./errors.ts";

/** A parsed JSON object: not null and not an array. */
export type JsonObject = Record<string, unknown>;

export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The value as a JSON object, or an InputError naming `what`. */
export function asObject(value: unknown, what: string): JsonObject {
  if (!isObject(value)) throw new InputError(`${what} must be a JSON object`);
  return value;
}

/** The value as a JSON array, or an InputError naming `what`. */
export function asList(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new InputError(`${what} must be a list`);
  return value;
}

/** JSON.parse, except an integer outside the safe range comes back as a bigint. */
export function parse(text: string): unknown {
  // The reviver's context.source is the literal's text, before it was rounded.
  return JSON.parse(text, (_key, value, context?: { source?: string }) =>
    typeof value === "number" &&
    !Number.isSafeInteger(value) &&
    context?.source !== undefined &&
    /^-?[0-9]+$/.test(context.source)
      ? BigInt(context.source)
      : value,
  );
}

/**
 * JSON.stringify(value, null, indent), except a bigint is written as its digits, a Map as an
 * object in insertion order, and any object other than a plain one, array or Map throws instead
 * of going through toJSON, so a Uint8Array or a class instance never reaches a file as some
 * accidental shape. A plain object puts integer-like keys such as "21" first, so files whose
 * key order mixes them (the native storage maps) are built as Maps.
 */
export function stringify(value: unknown, indent = 0): string {
  return write(value, { indent: " ".repeat(indent), canonical: false }, "") ?? refuseUndefined();
}

/**
 * One line with ", " and ": " separators, keys sorted by code point and every character
 * outside printable ASCII escaped. The check tools print their summary lines in this form, and
 * the native proof cache keys its files on it, so changing it would orphan existing caches.
 */
export function canonical(value: unknown): string {
  return write(value, { indent: "", canonical: true }, "") ?? refuseUndefined();
}

function refuseUndefined(): never {
  throw new TypeError("cannot write undefined as JSON");
}

interface Style {
  indent: string;
  canonical: boolean;
}

function write(value: unknown, style: Style, prefix: string): string | undefined {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return style.canonical ? asciiString(value) : JSON.stringify(value);
    case "number":
    case "boolean":
      return JSON.stringify(value);
    case "bigint":
      return value.toString();
    case "undefined":
    case "function":
    case "symbol":
      return undefined;
  }
  const nested = prefix + style.indent;
  const open = style.indent ? "\n" + nested : "";
  const close = style.indent ? "\n" + prefix : "";
  const comma = style.indent ? ",\n" + nested : style.canonical ? ", " : ",";
  const colon = style.indent || style.canonical ? ": " : ":";
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    // Array.from visits holes, which map skips, so a hole is written as null.
    const items = Array.from(value, (item) => write(item, style, nested) ?? "null");
    return "[" + open + items.join(comma) + close + "]";
  }
  const proto = Object.getPrototypeOf(value);
  let entries: [string, unknown][];
  if (value instanceof Map) entries = [...value].map(([key, item]) => [String(key), item]);
  else if (proto === Object.prototype || proto === null) entries = Object.entries(value as object);
  else throw new TypeError(`cannot write ${Object.prototype.toString.call(value)} as JSON`);
  if (style.canonical) entries.sort(([a], [b]) => byCodePoint(a, b));
  const members: string[] = [];
  for (const [key, item] of entries) {
    const text = write(item, style, nested);
    if (text !== undefined) members.push(write(key, style, nested) + colon + text);
  }
  if (members.length === 0) return "{}";
  return "{" + open + members.join(comma) + close + "}";
}

// Canonical keys sort by code point. JS "<" compares UTF-16 code units, which puts an astral
// character (a surrogate pair) before U+E000 to U+FFFF.
function byCodePoint(a: string, b: string): number {
  for (let i = 0; i < a.length && i < b.length;) {
    const x = a.codePointAt(i)!;
    const y = b.codePointAt(i)!;
    if (x !== y) return x - y;
    i += x > 0xffff ? 2 : 1;
  }
  return a.length - b.length;
}

// Every character outside space to "~" becomes \uXXXX (UTF-16 code units), except the short
// escapes for quote, backslash and five controls.
const SHORT_ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\b": "\\b",
  "\f": "\\f",
};

/**
 * The text with every C0 and C1 control character except newline and tab written as \uXXXX.
 * Text a node or a received file supplied goes through this before reaching a terminal, where
 * escape sequences could rewrite the screen or set the clipboard (OSC 52). JSON.stringify
 * escapes C0 controls only.
 */
export function printable(text: string): string {
  return text.replace(
    /[\x00-\x08\x0b-\x1f\x7f-\x9f]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

function asciiString(text: string): string {
  const escaped = text.replace(
    /["\\]|[^ -~]/g,
    (c) => SHORT_ESCAPES[c] ?? "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
  return `"${escaped}"`;
}
