/**
 * Refuses to build deployment bytecode with compiler settings nobody reviewed.
 *
 *   node tools/check-forge-config.ts MANIFEST CONTRACTS_ROOT
 *
 * forge resolves its settings from foundry.toml, FOUNDRY_* variables in any letter case,
 * .env files and the global ~/.foundry/foundry.toml, and it fills in defaults such as
 * evm_version from its own version. The deployment checks compare the chain with that same
 * local build, so they cannot notice a change. This asks forge what it would actually use, in
 * the caller's environment, and compares that with the settings the activation manifest pins.
 */
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";

import { parseArgs, runCli } from "../src/cli/args.ts";
import { CheckError } from "../src/errors.ts";
import { canonical, stringify } from "../src/json.ts";
import { field, get, object, parseInOrder, readText, utf8 } from "./check.ts";

// compilation_restrictions and additional_compiler_profiles compile matching files with other
// settings than the profile's, so they are pinned too.
const KEYS = (
  "solc optimizer optimizer_runs optimizer_details via_ir evm_version bytecode_hash " +
  "cbor_metadata use_literal_content revert_strings libraries remappings " +
  "compilation_restrictions additional_compiler_profiles"
).split(" ");

// Objects are Maps in file order, so profiles are checked in the manifest's order, and an
// integer is a bigint only outside the safe range, so 200 and 200.0 compare equal.
const parseConfig = (text: string) =>
  parseInOrder(text, (value, source) =>
    Number.isSafeInteger(value) || !/^-?[0-9]+$/.test(source) ? value : BigInt(source),
  );

// A missing key reads as null, so a setting absent on both sides matches.
const settings = (config: unknown, what: string) =>
  Object.fromEntries(KEYS.map((key) => [key, get(config, key, what)]));

/** Compares every profile the manifest pins with what forge resolves; returns the summary. */
function checkForgeConfig(manifest: unknown, root: string): string {
  const profiles = object(field(manifest, "compiler", "the manifest"), "compiler");
  for (const [profile, pins] of profiles) {
    // The default profile runs in the caller's environment unchanged, as the deployment's
    // plain forge calls do.
    const env = profile === "default" ? process.env : { ...process.env, FOUNDRY_PROFILE: profile };
    const result = spawnSync("forge", ["config", "--root", root, "--json"], { env });
    if (result.error || result.status !== 0) {
      const reason = result.error?.message ?? utf8.decode(result.stderr).trim();
      throw new CheckError(`forge config failed for profile ${profile}: ${reason}`);
    }
    const what = `forge config for profile ${profile}`;
    const actual = settings(parseConfig(utf8.decode(result.stdout)), what);
    const expected = settings(pins, `compiler.${profile}`);
    // Values compare deeply ([] equals []), and integers outside the safe range exactly.
    const drift = KEYS.filter((key) => !isDeepStrictEqual(actual[key], expected[key])).map(
      (key) => `${key}=${stringify(actual[key])} (pinned ${stringify(expected[key])})`,
    );
    if (drift.length > 0) {
      throw new CheckError(
        `forge resolves profile ${profile} differently from the manifest: ${drift.join(", ")}`,
      );
    }
  }
  return canonical({ compiler: "match", profiles: [...profiles.keys()].sort() });
}

if (import.meta.main) {
  await runCli(() => {
    const { positionals } = parseArgs(
      {
        prog: "check-forge-config.ts",
        positionals: [{ name: "manifest" }, { name: "contracts_root" }],
      },
      process.argv.slice(2),
    );
    const manifest = parseConfig(readText(positionals.manifest));
    process.stdout.write(checkForgeConfig(manifest, positionals.contracts_root) + "\n");
  });
}
