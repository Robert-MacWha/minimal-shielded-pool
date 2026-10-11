/**
 * Plumbing the test files share: running a CLI as a user would, and a local JSON-RPC node. It
 * holds no tests of its own.
 */
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

export type Env = Record<string, string | undefined>;

/**
 * How a run ended. A run that never started, died from a signal, or was killed by runCli's timeout
 * has code -1, and `signal` names the signal it died from or was sent.
 */
export type CliResult = {
  code: number;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
};

/**
 * Runs `command` with `args` and resolves with how it ended; it never rejects. Standard input is
 * closed, so nothing can wait on it, and the run is sent SIGTERM after `timeout` ms (60 s by
 * default), so a hang fails the test instead of stalling it. A killed run reports code -1 and
 * SIGTERM even when it catches the signal and exits with a status of its own, as the CLIs built on
 * src/cli/args.ts do (143), so a kill never reads as success. `env` replaces the caller's
 * environment, and NODE_TEST_CONTEXT is removed from either, so a child never reports to this test
 * runner.
 */
export function runCli(
  command: string,
  args: readonly string[],
  { cwd, env = process.env, timeout = 60_000 }: { cwd?: string; env?: Env; timeout?: number } = {},
): Promise<CliResult> {
  const options = {
    cwd,
    env: { ...env, NODE_TEST_CONTEXT: undefined },
    timeout,
    killSignal: "SIGTERM" as const,
    maxBuffer: 1 << 24,
  };
  return new Promise((resolve) => {
    const child = execFile(command, args, options, (error, stdout, stderr) => {
      // child.killed is set once the timeout (or the output limit) has signalled the child.
      const status = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
      const code = child.killed ? -1 : status;
      const signal = error?.signal ?? (child.killed ? options.killSignal : null);
      resolve({ code, signal, stdout, stderr });
    });
    child.stdin?.end();
  });
}

/** One call the local node received; `path` is the URL path it was sent to. */
export type RpcCall = { id: unknown; method: string; params: any; path: string };

/**
 * The reply to one call: its JSON-RPC `result` or `error`, sent with HTTP status 200 unless
 * `status` names another; or, with `redirect`, a 307 to that location and no body. With `part`,
 * the reply's text is written that many characters at a time, each part its own HTTP chunk.
 */
export type RpcReply = {
  result?: unknown;
  error?: unknown;
  status?: number;
  redirect?: string;
  part?: number;
};

/**
 * A JSON-RPC node on 127.0.0.1, at a port the system picks, that answers each call from `answer`
 * and records every call in `requests`, in order. close() also closes open connections, so it
 * never waits on a client's keep-alive. An error `answer` throws is left unhandled, so it fails
 * the test.
 */
export async function rpcServer(answer: (call: RpcCall) => RpcReply | Promise<RpcReply>) {
  const requests: RpcCall[] = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    const { id, method, params } = JSON.parse(body);
    const call = { id, method, params, path: request.url ?? "/" };
    requests.push(call);
    const { status = 200, redirect, part, ...reply } = await answer(call);
    if (redirect !== undefined) return void response.writeHead(307, { location: redirect }).end();
    const text = JSON.stringify({ jsonrpc: "2.0", id, ...reply });
    response.writeHead(status, { "content-type": "application/json" });
    if (part === undefined) return void response.end(text);
    for (let at = 0; at < text.length; at += part) response.write(text.slice(at, at + part));
    response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const close = () => {
    server.closeAllConnections();
    return new Promise<void>((resolve) => server.close(() => resolve()));
  };
  return { url, requests, close };
}
