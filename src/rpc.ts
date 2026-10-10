/**
 * The one JSON-RPC client. A node that answered with a JSON-RPC error gave a verdict
 * (RpcError); one that could not be reached or did not speak JSON-RPC gave none
 * (RpcTransportError), and refusals depend on the difference. Node's fetch honours HTTP_PROXY,
 * HTTPS_PROXY and NO_PROXY when NODE_USE_ENV_PROXY=1 is set.
 *
 * PoolNode is the node as the pool client calls it. RpcChain is the read-only view of the chain
 * that disclosure and note scanning use; whatever stops it answering is a ChainError, and
 * disclosure refuses the claim that needed the answer.
 */
import { fromHex, hexPadded, parseAddress, parseHex, toHex } from "./bytes.ts";
import { PoolError, UserError } from "./errors.ts";
import { isObject, parse, stringify } from "./json.ts";
import { NONCE_MANAGER_ADDRESS, nonceKeySlot } from "./protocol.ts";

/** The node answered with a JSON-RPC error object, or with neither error nor result. */
export class RpcError extends UserError {
  /** The error object as text, or "no result". */
  readonly detail: string;
  readonly code: number | undefined;

  constructor(method: string, error: unknown) {
    const detail =
      error === undefined ? "no result" : typeof error === "string" ? error : stringify(error);
    super(`${method} -> ${detail}`);
    this.detail = detail;
    const code = isObject(error) ? error.code : undefined;
    this.code = typeof code === "number" ? code : undefined;
  }
}

/** The node could not be reached, timed out, answered a non-2xx status or not with JSON-RPC. */
export class RpcTransportError extends UserError {
  constructor(method: string, reason: string) {
    super(`${method} request failed: ${reason}`);
  }
}

/** A Chain could not answer: its node failed or answered badly, or it lacks the transaction. */
export class ChainError extends UserError {}

/**
 * One JSON-RPC call, returning the reply's result, including null. A redirect is refused rather
 * than followed, and no failure reason repeats the URL, which can carry an API key.
 */
export async function rpc(
  url: string,
  method: string,
  params: readonly unknown[],
  { timeoutMs }: { timeoutMs: number },
): Promise<unknown> {
  const body = stringify({ jsonrpc: "2.0", id: 1, method, params });
  const fail = (reason: string) => new RpcTransportError(method, reason);
  if (!URL.canParse(url) || !/^https?:$/.test(new URL(url).protocol)) {
    throw fail("not a valid HTTP URL");
  }
  let response: Response;
  let text: string | null;
  try {
    const headers = { "content-type": "application/json" };
    const signal = AbortSignal.timeout(timeoutMs);
    response = await fetch(url, { method: "POST", headers, body, redirect: "error", signal });
    text = UNCAPPED.has(method)
      ? await response.text()
      : await cappedText(response, MAX_REPLY_BYTES);
  } catch (error) {
    throw fail(transportReason(error, timeoutMs));
  }
  if (!response.ok) throw fail(`HTTP ${response.status}`);
  if (text === null) throw fail(TOO_LARGE);
  let reply: unknown;
  try {
    reply = parse(text);
  } catch {
    throw fail("the reply is not JSON");
  }
  if (!isObject(reply)) throw fail("the reply is not a JSON-RPC object");
  if (Object.hasOwn(reply, "error")) throw new RpcError(method, reply.error);
  if (!Object.hasOwn(reply, "result")) throw new RpcError(method, undefined);
  return reply.result;
}

// parse()'s reviver reads each value's source text, so a reply of many tiny values can take over
// 100 times its size in heap: 64 MiB of them drive V8 to its default heap limit, and 200 MiB abort
// the process, skipping the exit handlers that release a wallet's state lock. A reply is read up
// to this cap, except a receipt's: anyone can fill a block with logs, and ethrex repeats each
// frame's logs in its receipt's top-level logs, so one block's receipts, or even one
// transaction's, can honestly pass the cap, and nothing splits them. A receipt reply is read
// whole, so the node, or anyone on a plain-http path to it, can still abort the process with one.
const MAX_REPLY_BYTES = 16 * 2 ** 20;
const UNCAPPED = new Set(["eth_getBlockReceipts", "eth_getTransactionReceipt"]);
/** rpc()'s reason for refusing a reply past the cap. */
export const TOO_LARGE = `the reply is larger than ${MAX_REPLY_BYTES >> 20} MiB`;

/**
 * The body as text, or null once it passes limit bytes, after which the rest is not read. Each
 * part is copied out as it arrives: a body sent in millions of one-byte parts would otherwise
 * hold an object per byte.
 */
async function cappedText(response: Response, limit: number): Promise<string | null> {
  let body = new Uint8Array(4096);
  let size = 0;
  for await (const part of response.body ?? []) {
    // Leaving the loop cancels the stream.
    if (size + part.length > limit) return null;
    if (size + part.length > body.length) {
      const larger = new Uint8Array(Math.min(limit, 2 * (size + part.length)));
      larger.set(body.subarray(0, size));
      body = larger;
    }
    body.set(part, size);
    size += part.length;
  }
  // As response.text() decodes: UTF-8, a leading byte order mark dropped.
  return new TextDecoder().decode(body.subarray(0, size));
}

// Node's error codes (ECONNREFUSED, ENOTFOUND) and fetch's own reasons ("unexpected
// redirect", "bad port") name no host, unlike the full error messages.
function transportReason(error: unknown, timeoutMs: number): string {
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return `timed out after ${timeoutMs} ms`;
  }
  const cause = (error as { cause?: { code?: unknown; message?: unknown } } | undefined)?.cause;
  if (typeof cause?.code === "string") return cause.code;
  if (typeof cause?.message === "string" && !cause.message.includes(":")) return cause.message;
  return "the node could not be reached";
}

// ---- the node, as the pool client calls it ----

/**
 * The node calls the pool client makes; tests pass a fake. `call` throws RpcError for an error
 * reply and RpcTransportError otherwise; `simulate` returns null when the node lacks the method.
 */
export interface PoolNode {
  call(method: string, params: readonly unknown[]): Promise<unknown>;
  simulate(raw: string): Promise<unknown>;
}

/**
 * The node at `url`, with a 20-second timeout. simulate dry-runs a signed frame transaction
 * through ethrex_simulateFrameTransaction, the frame-native eth_estimateGas; a transaction over
 * the gas cap comes back as a result with valid=false, not as an error.
 */
export function poolNode(url: string): PoolNode {
  const call = (method: string, params: readonly unknown[]) =>
    rpc(url, method, params, { timeoutMs: 20_000 });
  return {
    call,
    async simulate(raw) {
      try {
        return await call("ethrex_simulateFrameTransaction", [raw]);
      } catch (error) {
        if (!(error instanceof RpcError)) throw error;
        if (error.code === -32601) return null;
        throw new PoolError(`  simulate RPC error: ${error.detail}`);
      }
    },
  };
}

// ---- the chain, as disclosure and note scanning read it ----

/** A log as the node returns it; only these fields are read. */
export interface RawLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

/** A log from eth_getLogs, with its transaction hash in lower case. */
export type ChainLog = RawLog & { readonly tx: string };

export interface ChainFrame {
  readonly mode: bigint;
  /** The frame's target; a frame without one calls the transaction's sender. */
  readonly to: bigint;
  readonly data: Uint8Array;
  readonly status: bigint;
  readonly logs: readonly RawLog[];
}

export interface ChainTransaction {
  readonly hash: string;
  readonly sender: bigint;
  readonly block: bigint;
  readonly frames: readonly ChainFrame[];
  readonly logs: readonly RawLog[];
}

type Awaitable<T> = T | Promise<T>;

/**
 * What disclosure reads from a chain. A method that cannot answer throws a ChainError. Test
 * chains may answer synchronously.
 */
export interface Chain {
  chainId(): Awaitable<bigint>;
  finalizedBlock(): Awaitable<bigint>;
  transaction(hash: string): Awaitable<ChainTransaction>;
  logs(
    address: bigint,
    topics: readonly unknown[],
    fromBlock?: bigint,
  ): Awaitable<readonly ChainLog[]>;
  nonceUsed(sender: bigint, key: bigint): Awaitable<boolean>;
}

/** A node read over JSON-RPC. Any failure, a malformed answer included, is a ChainError. */
export class RpcChain implements Chain {
  readonly url: string;

  constructor(url: string) {
    this.url = url;
  }

  /** One call, with a 30-second timeout; tests override it to replay canned answers. */
  async call(method: string, params: readonly unknown[]): Promise<unknown> {
    try {
      return await rpc(this.url, method, params, { timeoutMs: 30_000 });
    } catch (error) {
      const cause = { cause: error };
      if (error instanceof RpcTransportError) throw new ChainError(error.message, cause);
      if (error instanceof RpcError) {
        throw new ChainError(`${method} failed: ${error.detail}`, cause);
      }
      throw error;
    }
  }

  async chainId(): Promise<bigint> {
    const result = await this.call("eth_chainId", []);
    return answer("eth_chainId", () => parseHex(result, "the chain id"));
  }

  async finalizedBlock(): Promise<bigint> {
    const block = await this.call("eth_getBlockByNumber", ["finalized", false]);
    return answer("eth_getBlockByNumber", () => {
      if (!isObject(block)) throw new Error("the node has no finalized block");
      return parseHex(block.number, "the block number");
    });
  }

  /** Whether EIP-8250's nonce manager has consumed this sender's nonce key. */
  async nonceUsed(sender: bigint, key: bigint): Promise<boolean> {
    const manager = hexPadded(NONCE_MANAGER_ADDRESS, 40);
    const slot = toHex(nonceKeySlot(sender, key));
    const result = await this.call("eth_getStorageAt", [manager, slot, "latest"]);
    return answer("eth_getStorageAt", () => parseHex(result, "the storage word") !== 0n);
  }

  /** A transaction with its frames and their outcomes, both looked up before either is read. */
  async transaction(hash: string): Promise<ChainTransaction> {
    const tx = await this.call("eth_getTransactionByHash", [hash]);
    const receipt = await this.call("eth_getTransactionReceipt", [hash]);
    // A node answers null for a hash it does not know.
    if (tx === null || receipt === null) {
      throw new ChainError(`transaction ${hash} is not on this chain`);
    }
    return answer(hash, () => {
      if (!isObject(tx) || !isObject(receipt)) throw new Error("not an object");
      // EIP-8141 frame transactions name their sender; legacy ones use from.
      const named = tx.sender ?? tx.from;
      if (named === undefined) throw new Error("the transaction names no sender");
      const sender = parseAddress(named, "sender");
      const frames = optionalList(tx.frames, "frames");
      const outcomes = optionalList(receipt.frameReceipts, "frameReceipts");
      if (frames.length !== outcomes.length) {
        throw new Error("frames and frame receipts differ in number");
      }
      return {
        hash,
        sender,
        block: parseHex(receipt.blockNumber, "blockNumber"),
        frames: frames.map((frame, i): ChainFrame => {
          const outcome = outcomes[i];
          if (!isObject(frame) || !isObject(outcome)) throw new Error("a frame is not an object");
          return {
            mode: parseHex(frame.mode, "mode"),
            to: frame.to == null ? sender : parseAddress(frame.to, "to"),
            data: fromHex(frame.data, "frame data"),
            status: parseHex(outcome.status, "status"),
            logs: rawLogs(outcome.logs),
          };
        }),
        logs: rawLogs(receipt.logs),
      };
    });
  }

  /**
   * The pool's logs from fromBlock to the latest block, 2,000 blocks per eth_getLogs call, as
   * notes scan reads them by default. One call over the whole history would pass rpc()'s cap
   * once the pool held about 25,000 shields.
   */
  async logs(address: bigint, topics: readonly unknown[], fromBlock = 0n): Promise<ChainLog[]> {
    const latest = await this.call("eth_blockNumber", []);
    const head = answer("eth_blockNumber", () => parseHex(latest, "the block number"));
    const logs: ChainLog[][] = [];
    for (let start = fromBlock; start <= head; start += 2000n) {
      const end = start + 1999n < head ? start + 1999n : head;
      const filter = {
        address: hexPadded(address, 40),
        topics,
        fromBlock: hexPadded(start, 1),
        toBlock: hexPadded(end, 1),
      };
      const found = await this.call("eth_getLogs", [filter]);
      const chunk = answer("eth_getLogs", () => {
        if (!Array.isArray(found)) throw new Error("not a list of logs");
        return found.map((log: unknown) => {
          const tx = isObject(log) ? log.transactionHash : undefined;
          if (typeof tx !== "string") throw new Error("a log has no transactionHash");
          return { tx: tx.toLowerCase(), ...rawLog(log) };
        });
      });
      logs.push(chunk);
    }
    return logs.flat();
  }
}

// Any parse failure inside an answer is the node's fault, reported as such.
function answer<T>(what: string, read: () => T): T {
  try {
    return read();
  } catch (error) {
    if (!(error instanceof Error) || error instanceof ChainError) throw error;
    const message = `unexpected RPC response for ${what}: ${error.message}`;
    throw new ChainError(message, { cause: error });
  }
}

// A legacy transaction has no frames or frame receipts: the node leaves them out or writes null.
function optionalList(value: unknown, what: string): unknown[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error(`${what} is not a list`);
  return value;
}

// A frame that failed may report null logs; it emitted none.
function rawLogs(value: unknown): RawLog[] {
  if (value === null) return [];
  if (!Array.isArray(value)) throw new Error("logs is not a list");
  return value.map(rawLog);
}

function rawLog(log: unknown): RawLog {
  if (
    !isObject(log) ||
    typeof log.address !== "string" ||
    typeof log.data !== "string" ||
    !Array.isArray(log.topics) ||
    !log.topics.every((topic) => typeof topic === "string")
  ) {
    throw new Error("a log lacks its address, topics or data");
  }
  return { address: log.address, topics: log.topics as string[], data: log.data };
}
