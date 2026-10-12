#!/usr/bin/env bash
# Deploy the single supported minimal-pool architecture to the ethrex testnet.
# Required: RPC_URL, DEPLOYER_KEYSTORE (a Foundry keystore file, made once with
# `cast wallet import NAME --interactive`) and DEPLOYER_PASSWORD_FILE (its
# password, readable only by you). No key goes on a command line, where any
# local user could read it. The repository key is a single-party testbed
# setup, so public-testnet use must explicitly set ALLOW_TESTBED_SETUP=1.
set -euo pipefail
cd "$(dirname "$0")"

RPC=${RPC_URL:?set RPC_URL}
: "${DEPLOYER_KEYSTORE:?set DEPLOYER_KEYSTORE to a Foundry keystore file}"
: "${DEPLOYER_PASSWORD_FILE:?set DEPLOYER_PASSWORD_FILE to its password file}"
# forge and cast sign with the keystore these name.
export ETH_KEYSTORE=$DEPLOYER_KEYSTORE ETH_PASSWORD=$DEPLOYER_PASSWORD_FILE
[[ ${ALLOW_TESTBED_SETUP:-0} == 1 ]] || {
  echo "refusing deployment: set ALLOW_TESTBED_SETUP=1 for the disposable testnet key" >&2
  echo "a production deployment requires a separately verified multi-party zkey" >&2
  exit 1
}
MANIFEST=../core/activation_manifest.testbed.json
node check-activation.ts "$MANIFEST" --allow-testbed

BN=../core/contracts
PRICE=(--gas-price 3000000000 --priority-gas-price 1000000000)
SMOKE_OUTPUT=${SMOKE_OUTPUT:-../artifacts/smoke_fixture.live.json}
# An earlier run's fixture holds the only secrets of the notes it left behind.
[[ ! -e $SMOKE_OUTPUT ]] || {
  echo "$SMOKE_OUTPUT exists and may hold the only secrets of unspent notes; move it or set SMOKE_OUTPUT" >&2
  exit 1
}
# forge resolves its settings from foundry.toml, FOUNDRY_* variables in any case,
# .env files and the global config, and every check below compares the chain with
# that same local build. Compare what forge would use with the manifest's pins.
node check-forge-config.ts "$MANIFEST" "$BN"
# The commit the record names, read before this script rewrites core/deploy_config.json;
# "-dirty" marks tracked files that differ from it.
REVISION=$(git rev-parse HEAD)
git diff --quiet HEAD || REVISION+=-dirty
deployed() { grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | awk '{print $3}'; }
# -e fails on a missing or null address instead of printing "null".
addr_of() { jq -er '.contractAddress'; }
# Cast annotates large ints as "550000000000000000 [5.5e17]". Keep the first token, which must
# be 0x hex or a decimal without leading zeros: BigInt("") would read an empty answer as 0.
cast_uint() {
  node -e 'const t = process.argv[1].trim().split(/\s+/)[0];
    if (!/^(0x[0-9a-fA-F]+|0+|[1-9][0-9]*)$/.test(t)) process.exit(1);
    console.log(BigInt(t).toString())' "$1"
}
# Balances outgrow Bash's 64-bit arithmetic: "uint_math add A B" or "uint_math sub A B".
uint_math() {
  node -e 'const [a, b] = process.argv.slice(2).map((x) => (/^[0-9]+$/.test(x) ? BigInt(x) : process.exit(1)));
    console.log(String(process.argv[1] === "add" ? a + b : a - b))' "$@"
}
# These checks run on the left of `||`, where Bash ignores `set -e`, so every
# read and comparison returns its own failure. Otherwise only the last line
# would decide the result.
verify_library_runtime() {
  local addr=$1 expected=$2 actual prefix actual_lower prefix_lower
  actual=$(cast code "$addr" --rpc-url "$RPC") || return 1
  prefix="0x73${addr#0x}"
  actual_lower=$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')
  prefix_lower=$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]')
  [[ $actual_lower == "$prefix_lower"* && ${actual:44} == "${expected:44}" ]]
}
verify_logic_runtime() {
  local addr=$1 expected=$2 actual t3 t4
  actual=$(cast code "$addr" --rpc-url "$RPC") || return 1
  # Zero the immutables, which the simulated deployment cannot know, then compare. The script
  # is indented: a line holding only "}" would end this function for test/deploy.test.ts.
  node - "$actual" "$expected" "$BN/out/ShieldedPoolLogic.sol/ShieldedPoolLogic.json" <<'JS' || return 1
    const [actualHex, expectedHex, artifact] = process.argv.slice(2);
    const hex = /^0x([0-9a-fA-F]{2})*$/;
    if (!hex.test(actualHex) || !hex.test(expectedHex)) process.exit(1);
    const actual = Buffer.from(actualHex.slice(2), "hex");
    const expected = Buffer.from(expectedHex.slice(2), "hex");
    // Strict UTF-8, and an offset written as 1.0 or 1e0 is not an integer.
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
      .decode(require("node:fs").readFileSync(artifact));
    const integer = (_, v, c) => (typeof v === "number" && !/^-?[0-9]+$/.test(c.source) ? NaN : v);
    const refs = JSON.parse(text, integer).deployedBytecode.immutableReferences;
    const isMap = typeof refs === "object" && refs !== null && !Array.isArray(refs);
    if (actual.length !== expected.length || !isMap) process.exit(1);
    for (const locations of Object.values(refs)) {
      for (const { start, length } of locations) {
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length)) process.exit(1);
        if (start < 0 || length < 0) process.exit(1);
        // A region past the end has nothing to zero, and both copies are clamped alike.
        const [from, to] = [start, start + length].map((i) => Math.min(i, actual.length));
        actual.fill(0, from, to);
        expected.fill(0, from, to);
      }
    }
    process.exit(actual.equals(expected) ? 0 : 1);
JS
  t4=$(cast call "$addr" 'POSEIDON_T4()(address)' --rpc-url "$RPC") || return 1
  [[ $t4 == "$T4" ]]
}
verify_created_runtime() {
  local addr=$1 initcode=$2 actual expected
  actual=$(cast code "$addr" --rpc-url "$RPC") || return 1
  expected=$(cast call --rpc-url "$RPC" --create "$initcode") || return 1
  [[ ${#expected} -gt 2 && $actual == "$expected" ]]
}

CHAIN_ID=$(cast chain-id --rpc-url "$RPC")
[[ $CHAIN_ID == 8141 ]] || { echo "wrong chain id: $CHAIN_ID (expected 8141)" >&2; exit 1; }
HEAD=$(cast rpc --rpc-url "$RPC" eth_getBlockByNumber latest false)
[[ $(jq -r '.slotNumber // empty' <<<"$HEAD") != "" ]] || {
  echo "RPC does not expose EIP-7843 slotNumber" >&2; exit 1;
}

DEPLOYER=$(cast wallet address)
# The CLI signs frame transactions itself. It gets the key once, decrypted into
# this shell, and reads it from a pipe that the builtin printf fills.
DEPLOYER_KEY=$(CAST_UNSAFE_PASSWORD=$(cat "$DEPLOYER_PASSWORD_FILE") cast wallet decrypt-keystore \
  --keystore-dir "$(dirname "$DEPLOYER_KEYSTORE")" "$(basename "$DEPLOYER_KEYSTORE")" | awk '{print $NF}')
funded_key() { printf '%s\n' "$DEPLOYER_KEY"; }
echo "==> deployer $DEPLOYER"
cast balance "$DEPLOYER" --rpc-url "$RPC" --ether || true

echo "==> Groth16 verifier (TESTBED zkey)"
VERIFIER=$(forge create --root "$BN" --rpc-url "$RPC" "${PRICE[@]}" \
  --gas-limit 6000000 --broadcast src/Groth16Verifier.sol:Groth16Verifier | deployed)
VERIFIER_CODE=$(forge inspect --root "$BN" src/Groth16Verifier.sol:Groth16Verifier deployedBytecode)
[[ $(cast code "$VERIFIER" --rpc-url "$RPC") == "$VERIFIER_CODE" ]] || {
  echo "verifier runtime mismatch" >&2; exit 1;
}
echo "    verifier=$VERIFIER"

echo "==> immutable Poseidon library"
T4=$(FOUNDRY_PROFILE=libsmall forge create --root "$BN" --rpc-url "$RPC" \
  "${PRICE[@]}" --gas-limit 16000000 --broadcast src/PoseidonT4.sol:PoseidonT4 | deployed)
T4_CODE=$(FOUNDRY_PROFILE=libsmall forge inspect --root "$BN" src/PoseidonT4.sol:PoseidonT4 deployedBytecode)
echo "    poseidonT4=$T4"
verify_library_runtime "$T4" "$T4_CODE" || { echo "PoseidonT4 runtime mismatch"; exit 1; }

echo "==> settlement logic"
LOGIC=$(forge create --root "$BN" --rpc-url "$RPC" "${PRICE[@]}" \
  --gas-limit 14000000 --broadcast src/ShieldedPoolLogic.sol:ShieldedPoolLogic \
  --constructor-args "$T4" | deployed)
LOGIC_BYTECODE=$(forge inspect --root "$BN" src/ShieldedPoolLogic.sol:ShieldedPoolLogic bytecode)
LOGIC_ARGS=$(cast abi-encode 'constructor(address)' "$T4")
LOGIC_INIT="${LOGIC_BYTECODE}${LOGIC_ARGS#0x}"
EXPECTED_LOGIC=$(cast call --rpc-url "$RPC" --create "$LOGIC_INIT")
verify_logic_runtime "$LOGIC" "$EXPECTED_LOGIC" || {
  echo "logic runtime mismatch" >&2; exit 1;
}
echo "    logic=$LOGIC"

echo "==> immutable dispatcher/pool"
# The pinned initcode, not a fresh compile, linked to the verified logic and verifier.
DISP_ARGS=$(cast abi-encode 'f(address,address)' "$LOGIC" "$VERIFIER")
DISP_INIT="$(cat ../core/artifacts/shielded_pool_dispatcher_init.hex)${DISP_ARGS#0x}"
# The creation receipt gives the pool's address and its deployment block, from which
# note scans and disclosure exports start reading logs.
POOL_RECEIPT=$(cast send --rpc-url "$RPC" "${PRICE[@]}" --gas-limit 4000000 \
  --create "$DISP_INIT" --json)
POOL=$(printf '%s' "$POOL_RECEIPT" | addr_of)
POOL_BLOCK=$(cast_uint "$(printf '%s' "$POOL_RECEIPT" | jq -er '.blockNumber')") || {
  echo "the pool's creation receipt has no block number" >&2; exit 1;
}
verify_created_runtime "$POOL" "$DISP_INIT" || {
  echo "dispatcher runtime mismatch" >&2; exit 1;
}

SOURCE0=$(cast call "$POOL" 'sourceId(uint64)(bytes32)' 0 --rpc-url "$RPC")
DOMAIN=$(cast call "$POOL" 'domain(uint64)(bytes32)' 0 --rpc-url "$RPC")
echo "    pool=$POOL source0=$SOURCE0 domain=$DOMAIN"

echo "==> RejectEther recipient (starts rejecting so a seed claim can leave credit)"
REJECTER=$(forge create --root "$BN" --rpc-url "$RPC" "${PRICE[@]}" \
  --gas-limit 1000000 --broadcast test/DispatcherPool.t.sol:RejectEther | deployed)
echo "    rejecter=$REJECTER"

echo "==> deployment-bound proofs"
# Fresh secrets: with the fixed fixture seed, anyone could rebuild these notes'
# keys and one-time authorizers and sweep what a live run leaves behind.
node ../src/cli/smoke.ts --random --chain-id="$CHAIN_ID" --pool-address="$POOL" \
  --recipient="$REJECTER" --output="$SMOKE_OUTPUT"

# The shield below checks the label, chain, and deployed code against this stub, so it
# carries the profile and the logic and verifier verified above.
MANIFEST_PATH=$MANIFEST node - "$RPC" "$POOL" "$LOGIC" "$VERIFIER" <<'JS'
const fs = require("node:fs");
const [rpc, pool, logic, verifier] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(process.env.MANIFEST_PATH, "utf8")).profile;
const need = (key) => (Object.hasOwn(manifest, key) ? manifest[key] : process.exit(1));
const stub = { rpc, pool, logic, verifier, chainId: need("chain_id"), profile: need("wire_profile") };
fs.writeFileSync("../core/deploy_config.json", JSON.stringify(stub, null, 1));
JS

echo "==> shield fixture note"
funded_key | node ../src/cli/pool.ts "$RPC" ../core/deploy_config.json "$SMOKE_OUTPUT" shield

# Publish the current tree root and echo the EIP-7843 slot its block landed in. Each
# spend proof is bound to the root that existed when it was generated, so a spend that
# changes the tree invalidates the root the next one needs: the transfer and the withdraw
# are bound to different roots and each needs its own publication.
publish_root() {
  funded_key | node ../src/cli/pool.ts "$RPC" ../core/deploy_config.json ../core/deploy_config.json publish --epoch 0 \
    | tee /dev/stderr \
    | sed -n 's/^ROOT_SLOT //p' | tail -1
}

echo "==> publish authenticated post-shield root"
ROOT_SLOT_DEC=$(publish_root) || exit 1
[[ -n $ROOT_SLOT_DEC ]] || { echo "publishEpochRoot did not emit ROOT_SLOT" >&2; exit 1; }

MANIFEST_PATH=$MANIFEST node - "$RPC" "$POOL" "$VERIFIER" "$T4" "$LOGIC" "$SOURCE0" "$DOMAIN" "$ROOT_SLOT_DEC" "$REVISION" "$POOL_BLOCK" <<'JS'
const fs = require("node:fs");
const keys = ["rpc", "pool", "verifier", "poseidonT4", "logic",
  "sourceIdEpoch0", "domain", "_slot_transfer"];
const cfg = Object.fromEntries(keys.map((key, i) => [key, process.argv[i + 2]]));
const [revision, deploymentBlock] = process.argv.slice(keys.length + 2);
// The gas figures come from the manifest this deployment was actually gated on, not
// from literals. A deployment of the updated dispatcher that wrote the frozen profile's
// 2,000,000 single budget would hand the spend wallet budgets belonging to a contract it
// is not talking to, and the resulting settlement failures look like proof errors.
const manifest = JSON.parse(fs.readFileSync(process.env.MANIFEST_PATH, "utf8")).profile;
const need = (key) => (Object.hasOwn(manifest, key) ? manifest[key] : process.exit(1));
// This file is the deployment record, and tools/check-gas-profile.ts reads the
// budgets back.
Object.assign(cfg, { chainId: need("chain_id"), profile: need("wire_profile"),
  verifyGas: need("verify_frame_gas"),
  settleGas: need("settle_frame_gas"),
  testbedProvingKey: true,
  settleStateGas: need("settle_frame_state_gas"),
  verifyStateGas: need("verify_frame_state_gas"),
  recentRootGas: need("recent_root_frame_gas"),
  claimGas: need("claim_frame_gas"),
  claimStateGas: need("claim_frame_state_gas") });
// The commit the deployment was built from, and the block note scans start from.
Object.assign(cfg, { revision, deploymentBlock: Number(deploymentBlock) });
fs.writeFileSync("../core/deploy_config.json", JSON.stringify(cfg, null, 1) + "\n");
console.log("wrote ../core/deploy_config.json");
JS

echo "==> deployed testbed pool"
echo "    fixture=$SMOKE_OUTPUT"
echo "    root slot=$ROOT_SLOT_DEC (EIP-7843 slotNumber, not block timestamp)"

# A deployment that only shields proves the pool can take money, not that it can pay it
# out. The spends exercise the proof, the nullifiers, the recent-root reference and the
# settlement frame's gas. SPEND=0 skips them for a deployment that only publishes a pool.
if [[ ${SPEND:-1} == 1 ]]; then
  echo "==> transfer (shielded spend, note -> note)"
  node ../src/cli/pool.ts "$RPC" ../core/deploy_config.json "$SMOKE_OUTPUT" transfer

  # The transfer inserted two commitments, so the root the withdraw proof was generated
  # against is the post-transfer one, not the post-shield one already published. Publish
  # again and record its slot under the key the withdraw reads.
  echo "==> publish authenticated post-transfer root"
  WITHDRAW_SLOT=$(publish_root) || exit 1
  node - "$WITHDRAW_SLOT" <<'JS'
const fs = require("node:fs");
const cfg = JSON.parse(fs.readFileSync("../core/deploy_config.json", "utf8"));
cfg._slot_withdraw = process.argv[2];
fs.writeFileSync("../core/deploy_config.json", JSON.stringify(cfg, null, 1));
console.log(`    withdraw root slot=${process.argv[2]}`);
JS

  # Leave real withdrawalCredit on the recipient so the existing
  # credit_before + publicAmount check is not vacuously 0 + publicAmount.
  # Alice's change exits to the same recipient; sinks do not change the root.
  echo "==> seed prior credit (withdraw_seed claim expected to revert)"
  node ../src/cli/pool.ts "$RPC" ../core/deploy_config.json "$SMOKE_OUTPUT" withdraw \
    --spend-key withdraw_seed --allow-failed-claim

  # The fixture holds these as JSON strings; -e fails on a missing or null one.
  RECIPIENT=$(jq -er '.recipient' "$SMOKE_OUTPUT")
  SEED_AMOUNT=$(jq -er '.withdraw_seed.public_amount' "$SMOKE_OUTPUT")
  PUBLIC_AMOUNT=$(jq -er '.withdraw.public_amount' "$SMOKE_OUTPUT")
  CREDIT_BEFORE=$(cast_uint "$(cast call "$POOL" 'withdrawalCredit(address)(uint256)' "$RECIPIENT" --rpc-url "$RPC")")
  [[ "$CREDIT_BEFORE" == "$SEED_AMOUNT" && "$CREDIT_BEFORE" != 0 ]] || {
    echo "seed did not leave expected credit: got $CREDIT_BEFORE want $SEED_AMOUNT" >&2; exit 1; }
  cast send "$REJECTER" 'setReject(bool)' false --rpc-url "$RPC" \
    "${PRICE[@]}" --gas-limit 100000 >/dev/null
  BEFORE=$(cast_uint "$(cast balance "$RECIPIENT" --rpc-url "$RPC")")
  EXPECTED=$(uint_math add "$CREDIT_BEFORE" "$PUBLIC_AMOUNT")
  echo "==> withdraw (shielded spend + claim, note -> recipient $RECIPIENT, expecting +$EXPECTED wei including prior credit $CREDIT_BEFORE)"
  node ../src/cli/pool.ts "$RPC" ../core/deploy_config.json "$SMOKE_OUTPUT" withdraw
  AFTER=$(cast_uint "$(cast balance "$RECIPIENT" --rpc-url "$RPC")")
  CREDIT_AFTER=$(cast_uint "$(cast call "$POOL" 'withdrawalCredit(address)(uint256)' "$RECIPIENT" --rpc-url "$RPC")")
  # claimWithdrawal pays all credit already held for the recipient, not just this
  # spend's publicAmount.
  PAID=$(uint_math sub "$AFTER" "$BEFORE")
  [[ $PAID == "$EXPECTED" ]] || {
    echo "withdraw paid $PAID wei to the recipient, expected $EXPECTED" >&2; exit 1; }
  [[ $CREDIT_AFTER == 0 ]] || {
    echo "recipient credit remaining after claim: $CREDIT_AFTER" >&2; exit 1; }
  echo "    recipient +$PAID wei ($BEFORE -> $AFTER); credit $CREDIT_BEFORE -> 0"
  echo "==> spends settled"
fi
