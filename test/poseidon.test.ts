/**
 * src/poseidon.ts against circomlibjs, through the vectors tools/export-vectors.ts wrote from
 * it: 16 inputs each for Poseidon(2) and Poseidon(3), the pool's tagged hash chain and an owner
 * set's root. The circuit, the Solidity library and the client share
 * these constants, so a mismatch here means the client computes notes the pool cannot match.
 * tools/export-vectors.ts and tools/poseidon-sol.ts must still write the committed vectors,
 * constants and Solidity libraries; that check needs forge on PATH. Runtime: about 1.5 s.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

import { OwnerSet } from "../src/owner.ts";
import { poseidon } from "../src/poseidon.ts";
import * as protocol from "../src/protocol.ts";

const { TAG_LEAF, TAG_PK, p2, tagged } = protocol;
const ROOT = resolve(import.meta.dirname, "..");
const vectors = JSON.parse(
  readFileSync(new URL("vectors/poseidon_bn254_vectors.json", import.meta.url), "utf8"),
  (_key, value) => (typeof value === "string" ? BigInt(value) : value),
);

for (const width of ["poseidon2", "poseidon3"]) {
  test(`${width} matches circomlibjs`, () => {
    const cases: { in: bigint[]; out: bigint }[] = vectors[width];
    assert.equal(cases.length, 16);
    for (const [i, v] of cases.entries()) {
      assert.equal(poseidon(v.in), v.out, `${width} vector ${i}`);
    }
  });
}

test("the pool's hash chain matches circomlibjs", () => {
  const c: Record<string, bigint> = vectors.pool_chain;
  const pk = tagged(TAG_PK, c.owner_root, c.nk);
  const inner = p2(pk, c.rho);
  const cm = tagged(TAG_LEAF, inner, c.value);
  // The domain includes the input epoch, and the index distinguishes copies of a commitment. The
  // tag is the literal 4, as in spend.circom, so the check does not rest on the library's own
  // constant.
  const nf = (leaf: bigint, index: bigint) => tagged(4n, p2(c.domain, c.nk), p2(leaf, index));
  assert.equal(pk, c.owner_pk, "owner_pk");
  assert.equal(inner, c.inner, "inner");
  assert.equal(cm, c.cm, "cm");
  assert.equal(nf(cm, c.index), c.nf, "nf");
  assert.equal(nf(tagged(TAG_LEAF, inner, 0n), 0n), c.nf2, "nf2");
  assert.equal(tagged(TAG_LEAF, c.out_inner1, c.out_value1), c.out_cm1, "out_cm1");
  assert.equal(tagged(TAG_LEAF, c.out_inner2, c.out_value2), c.out_cm2, "out_cm2");
  // The named helpers the wallet uses compose the same chain.
  assert.equal(protocol.ownerPk(c.owner_root, c.nk), c.owner_pk, "ownerPk()");
  assert.equal(protocol.inner(c.owner_pk, c.rho), c.inner, "inner()");
  assert.equal(protocol.commitment(c.owner_pk, c.rho, c.value), c.cm, "commitment()");
  assert.equal(protocol.nullifier(c.domain, c.nk, c.cm, c.index), c.nf, "nullifier()");
});

test("an owner set's root matches circomlibjs, with empty leaves 0", () => {
  const o = vectors.owner_set;
  assert.equal(o.depth, protocol.OWNER_DEPTH);
  let zero = 0n;
  for (let d = 0; d < protocol.OWNER_DEPTH; d++) zero = p2(zero, zero);
  assert.equal(zero, o.root_empty);
  assert.equal(new OwnerSet(o.addresses).root, o.root);
});

// Each generator writes into the checkout it runs from, so both run from copies under a
// temporary root that links back only to tools/check.ts and node_modules.
test("export-vectors, then poseidon-sol and forge fmt, write the committed files", (t) => {
  const root = mkdtempSync(join(tmpdir(), "poseidon-generators-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "core/contracts/src"), { recursive: true });
  mkdirSync(join(root, "tools"));
  for (const tool of ["export-vectors.ts", "poseidon-sol.ts"]) {
    copyFileSync(join(ROOT, "tools", tool), join(root, "tools", tool));
  }
  symlinkSync(join(ROOT, "tools/check.ts"), join(root, "tools/check.ts"));
  symlinkSync(join(ROOT, "node_modules"), join(root, "node_modules"));
  const run = (command: string, args: string[]) =>
    execFileSync(command, args, { cwd: root, stdio: "pipe" });
  run(process.execPath, ["tools/export-vectors.ts"]);
  run(process.execPath, ["tools/poseidon-sol.ts"]);
  const libraries = ["PoseidonT3", "PoseidonT4", "PoseidonBN254"].map(
    (name) => `core/contracts/src/${name}.sol`,
  );
  run("forge", ["fmt", "--root", join(ROOT, "core/contracts"), ...libraries]);
  const json = ["test/vectors/poseidon_bn254_vectors.json", "src/poseidon-constants.json"];
  for (const file of [...json, ...libraries]) {
    assert.equal(readFileSync(join(root, file), "utf8"), readFileSync(join(ROOT, file), "utf8"));
  }
});
