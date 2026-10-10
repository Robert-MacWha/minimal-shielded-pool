/**
 * The command-line parser every CLI uses: node:util's parseArgs in strict mode, with named and
 * checked positionals, integer options and help on top. An unknown or abbreviated flag stops the
 * run with exit status 2 before any file or RPC is touched (a mistyped --dry-run must not send a
 * transaction), --flag=value equals --flag value, and everything after "--" is positional.
 *
 * Any local user can read a process's arguments, and a parser error repeats what it rejects, so
 * every parser message has each run of 64 or more hex digits redacted: a key pasted anywhere on
 * the command line is refused without being echoed.
 */
import { inspect, parseArgs as parseArgv, type ParseArgsOptionsConfig } from "node:util";

import { parseDec, parseUint } from "../bytes.ts";
import { InputError, UserError } from "../errors.ts";
import { printable } from "../json.ts";

/** The text with every run of 64 or more hex digits, which may be a key, redacted. */
export function redact(text: string): string {
  return text.replace(/(0x)?[0-9a-fA-F]{64,}/g, "<redacted>");
}

export interface PositionalSpec {
  readonly name: string;
  readonly choices?: readonly string[];
  readonly help?: string;
}

/**
 * An option: a flag (true when given), one value (the last one given wins), or a repeated value
 * collected in order. "int" reads what parseUint reads from text: 0x hex or decimal without
 * leading zeros, since 010 could mean ten or eight. "decimal" reads decimal digits only, as
 * parseDec does. Neither takes a sign.
 */
export interface OptionSpec {
  readonly kind: "flag" | "string" | "int" | "decimal" | "append";
  readonly required?: boolean;
  readonly help?: string;
}

export interface CliSpec {
  readonly prog: string;
  readonly description?: string;
  readonly positionals?: readonly PositionalSpec[];
  readonly options?: { readonly [flag: `--${string}`]: OptionSpec };
  /** Refuses the argument at this index unless it starts with "--", before parsing (exit 1). */
  readonly refuseBeforeParsing?: { readonly index: number; readonly message: string };
}

type Positionals<S extends CliSpec> = S extends { positionals: readonly PositionalSpec[] }
  ? S["positionals"][number]
  : never;
type Options<S extends CliSpec> = S extends { options: infer O } ? O : {};
type OptionValue<O> = O extends { kind: "flag" }
  ? boolean
  : O extends { kind: "append" }
    ? string[]
    : (O extends { kind: "int" | "decimal" } ? bigint : string) | Missing<O>;
type Missing<O> = O extends { required: true } ? never : undefined;

export interface ParsedArgs<S extends CliSpec> {
  readonly positionals: {
    readonly [P in Positionals<S> as P["name"]]: P extends { choices: readonly (infer C)[] }
      ? C
      : string;
  };
  readonly options: { readonly [K in keyof Options<S>]: OptionValue<Options<S>[K]> };
}

/** A malformed command line: exit status 2, with the usage line and the redacted message. */
export class UsageError extends UserError {
  /** Everything to write to stderr. */
  readonly text: string;

  constructor(spec: CliSpec, message: string) {
    super(redact(message));
    this.text = `${usage(spec)}\n${spec.prog}: error: ${this.message}\n`;
  }
}

/** -h or --help: the help goes to stdout and the CLI exits 0. */
export class HelpRequested extends UserError {
  readonly text: string;

  constructor(spec: CliSpec) {
    super(help(spec));
    this.text = this.message;
  }
}

/** Parses argv against spec, or throws UsageError, HelpRequested or InputError. */
export function parseArgs<const S extends CliSpec>(
  spec: S,
  argv: readonly string[],
): ParsedArgs<S> {
  const refusal = spec.refuseBeforeParsing;
  if (refusal && argv.length > refusal.index && !argv[refusal.index].startsWith("--")) {
    throw new InputError(refusal.message);
  }
  const end = argv.indexOf("--");
  if ((end < 0 ? argv : argv.slice(0, end)).some((arg) => arg === "-h" || arg === "--help")) {
    throw new HelpRequested(spec);
  }
  const fail = (message: string): never => {
    throw new UsageError(spec, message);
  };
  const optionSpecs = Object.entries(spec.options ?? {});
  const config: ParseArgsOptionsConfig = {};
  for (const [flag, { kind }] of optionSpecs) {
    config[flag.slice(2)] = {
      type: kind === "flag" ? "boolean" : "string",
      // An int or decimal option keeps every value given, so that a malformed one is refused
      // even when a later one is valid.
      multiple: kind !== "flag" && kind !== "string",
    };
  }
  let parsed;
  try {
    // Strict mode refuses unknown flags, a value given to a flag, and a missing value. A value
    // that starts with "-" must be written --flag=value, so a flag is never taken as a value.
    parsed = parseArgv({ args: [...argv], options: config, allowPositionals: true, strict: true });
  } catch (error) {
    // Node's refusals of a command line carry an ERR_PARSE_ARGS_ code; anything else is a bug.
    if (!String((error as { code?: unknown }).code).startsWith("ERR_PARSE_ARGS_")) throw error;
    // Node ends an unknown-option refusal with a tip on passing a dash-led positional after
    // "--"; for a mistyped flag that is the wrong remedy.
    return fail((error as Error).message.split(". To specify a positional")[0]);
  }
  const { values, positionals } = parsed;
  const positionalSpecs = spec.positionals ?? [];
  const missing = [
    ...positionalSpecs.slice(positionals.length).map((p) => p.name),
    ...optionSpecs
      .filter(([flag, option]) => option.required && values[flag.slice(2)] === undefined)
      .map(([flag]) => flag),
  ];
  if (missing.length > 0) fail(`missing ${missing.join(", ")}`);
  if (positionals.length > positionalSpecs.length) {
    fail(`unexpected argument ${quote(positionals[positionalSpecs.length])}`);
  }
  positionalSpecs.forEach(({ name, choices }, i) => {
    if (choices && !choices.includes(positionals[i])) {
      fail(`${name} must be one of ${choices.join(", ")}, not ${quote(positionals[i])}`);
    }
  });

  const options = optionSpecs.map(([flag, { kind }]) => {
    const value = values[flag.slice(2)];
    if (kind === "flag") return [flag, value === true];
    if (kind === "append") return [flag, value ?? []];
    if (kind === "string" || value === undefined) return [flag, value];
    try {
      const read = (raw: string) => (kind === "int" ? parseUint(raw, flag) : parseDec(raw, flag));
      return [flag, (value as string[]).map(read).at(-1)];
    } catch (error) {
      return fail((error as Error).message);
    }
  });
  return {
    positionals: Object.fromEntries(positionalSpecs.map((p, i) => [p.name, positionals[i]])),
    options: Object.fromEntries(options),
  } as ParsedArgs<S>;
}

// Quotes a rejected value so that spaces and control characters stay visible.
function quote(text: string): string {
  return JSON.stringify(text);
}

/** How usage and help show an option: the flag, then a placeholder for its value. */
function shown(flag: string, option: OptionSpec): string {
  if (option.kind === "flag") return flag;
  return `${flag} ${flag.slice(2).replaceAll("-", "_").toUpperCase()}`;
}

/** The usage line: the program, [options], then any required options and the positionals. */
function usage(spec: CliSpec): string {
  const required = Object.entries(spec.options ?? {})
    .filter(([, option]) => option.required)
    .map(([flag, option]) => shown(flag, option));
  const positionals = (spec.positionals ?? []).map((p) =>
    p.choices ? `{${p.choices.join(",")}}` : p.name,
  );
  return ["usage:", spec.prog, "[options]", ...required, ...positionals].join(" ");
}

/** The usage line, the description, then one row per argument with its help beside it. */
function help(spec: CliSpec): string {
  const rows = [
    ...(spec.positionals ?? []).map((p) => {
      return [p.name, p.help ?? (p.choices ? `one of ${p.choices.join(", ")}` : "")];
    }),
    ...Object.entries(spec.options ?? {}).map(([flag, o]) => [shown(flag, o), o.help ?? ""]),
    ["-h, --help", "show this help message and exit"],
  ];
  const width = Math.max(...rows.map(([left]) => left.length));
  const lines = rows.map(([left, text]) => `  ${left.padEnd(width)}  ${text}`.trimEnd());
  const description = spec.description ? [spec.description, ""] : [];
  return [usage(spec), "", ...description, ...lines].join("\n") + "\n";
}

/**
 * Runs a CLI's main and turns its refusals into exit statuses, so that no CLI calls process.exit
 * and piped stdout always flushes: help exits 0 on stdout, a usage error 2, and any other
 * UserError 1 with its message on stderr. A failed system call, such as a file that cannot be
 * read, is reported in the same one line, and is always redacted as parser messages are: its
 * path came from the command line, where a key may have been pasted. Anything else is a bug,
 * printed with its stack trace.
 *
 * With redactErrors, which pool, notes, smoke and nonce-race set, all error output is redacted:
 * a key typed where a path or address belongs passes the parser and would come back in a
 * refusal. disclosure prints refusals as they are, since they name commitments users need.
 * prefix, which notes sets, begins each refusal and system error.
 */
export async function runCli(
  main: () => void | Promise<void>,
  options: { redactErrors?: boolean; prefix?: string } = {},
): Promise<void> {
  const { redactErrors = false, prefix = "" } = options;
  // Exiting through process.exit runs "exit" listeners, which release state locks; Node's
  // default handling of these signals would skip them. SIGHUP comes from a closed terminal.
  process.once("SIGINT", () => process.exit(130));
  process.once("SIGTERM", () => process.exit(143));
  process.once("SIGHUP", () => process.exit(129));
  try {
    await main();
  } catch (error) {
    if (error instanceof HelpRequested) {
      process.stdout.write(error.text);
    } else if (error instanceof UsageError) {
      process.stderr.write(error.text);
      process.exitCode = 2;
    } else {
      const system = error instanceof Error && "syscall" in error;
      const refusal = error instanceof UserError || system;
      // A refusal can quote a node's answer, so control characters are escaped.
      const text = printable(refusal ? prefix + (error as Error).message : inspect(error));
      process.stderr.write((redactErrors || system ? redact(text) : text) + "\n");
      process.exitCode = 1;
    }
  }
}
