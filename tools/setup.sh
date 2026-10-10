#!/usr/bin/env bash
# Compile the spend circuit and run a TESTBED-ONLY Groth16 setup.
#
#   tools/setup.sh              # compile + ceremony + verifier export
#
# Groth16 needs a circuit-specific trusted setup. This script runs the whole
# ceremony locally with entropy from /dev/urandom, which is fine for a testbed
# and for Sepolia demos but is NOT a production ceremony: whoever runs it
# could keep the toxic waste and forge proofs for themselves. A real
# deployment replaces phase 1 with a public powers-of-tau (e.g. the Hermez
# ceremony file) and runs a multi-party phase 2. Set PTAU=/path/to/final.ptau
# to use an externally sourced phase-1 file.
#
# Outputs (the setup works in the gitignored build/; these tracked artifacts
# are copied out of it or exported in place):
#   core/artifacts/spend.r1cs, core/artifacts/spend_js/spend.wasm   circuit
#   core/artifacts/spend_final.zkey                proving key (~8 MB)
#   core/contracts/src/Groth16Verifier.sol         committed, snarkjs-generated
#   core/artifacts/spend_vkey.json                 committed verification key
#
# The committed verifier and proof fixtures are mutually consistent.
# Re-running this script re-randomises phase 2 and replaces the proving key,
# verification key, and verifier. Run src/cli/smoke.ts afterwards, then
# update core/activation_manifest.testbed.json before treating the result as usable.
set -euo pipefail
# A relative PTAU names a file in the directory the script was started from.
[[ -z ${PTAU:-} || $PTAU == /* ]] || PTAU=$PWD/$PTAU
# From the repository root: circom2 runs under WASI and finds circomlib only through an
# include path inside its working directory.
cd "$(dirname "$0")/.."
# The circom2 and snarkjs that `npm ci` pins. npx would run a copy found in any parent
# directory's node_modules, or install the latest release, without asking when stdin is not
# a terminal.
CIRCOM=node_modules/.bin/circom2 SNARKJS=node_modules/.bin/snarkjs
[[ -x $CIRCOM && -x $SNARKJS ]] || { echo "run npm ci first: setup needs the pinned circom2 and snarkjs" >&2; exit 1; }

BUILD=build
ARTIFACTS=core/artifacts
mkdir -p "$BUILD"

echo "==> compiling spend.circom (circom $("$CIRCOM" --version | tail -1 | awk '{print $3}'))"
"$CIRCOM" core/circuits/spend.circom --r1cs --wasm --sym -l node_modules -o "$BUILD"
"$SNARKJS" r1cs info "$BUILD/spend.r1cs"

if [ -n "${PTAU:-}" ]; then
  echo "==> using external powers of tau: $PTAU"
  cp "$PTAU" "$BUILD/pot_final.ptau"
else
  echo "==> TESTBED phase 1: local powers of tau (power 14)"
  "$SNARKJS" powersoftau new bn128 14 "$BUILD/pot14_0.ptau" -v >/dev/null
  "$SNARKJS" powersoftau contribute "$BUILD/pot14_0.ptau" "$BUILD/pot14_1.ptau" \
    --name="testbed" -e="$(head -c 64 /dev/urandom | base64)" >/dev/null
  "$SNARKJS" powersoftau prepare phase2 "$BUILD/pot14_1.ptau" "$BUILD/pot_final.ptau" -v >/dev/null
fi

echo "==> phase 2: circuit-specific zkey"
"$SNARKJS" groth16 setup "$BUILD/spend.r1cs" "$BUILD/pot_final.ptau" "$BUILD/spend_0.zkey" >/dev/null
"$SNARKJS" zkey contribute "$BUILD/spend_0.zkey" "$BUILD/spend_final.zkey" \
  --name="testbed" -e="$(head -c 64 /dev/urandom | base64)" >/dev/null
"$SNARKJS" zkey verify "$BUILD/spend.r1cs" "$BUILD/pot_final.ptau" "$BUILD/spend_final.zkey" >/dev/null
cp "$BUILD/spend.r1cs" "$BUILD/spend_final.zkey" "$ARTIFACTS/"
cp "$BUILD/spend_js/spend.wasm" "$ARTIFACTS/spend_js/"

echo "==> exporting the verification key and the Solidity verifier"
"$SNARKJS" zkey export verificationkey "$BUILD/spend_final.zkey" "$ARTIFACTS/spend_vkey.json"
"$SNARKJS" zkey export solidityverifier "$BUILD/spend_final.zkey" core/contracts/src/Groth16Verifier.sol
node tools/patch-verifier.ts
( cd core/contracts && forge fmt src/Groth16Verifier.sol )

echo "==> done: core/artifacts/spend_final.zkey (proving), core/contracts/src/Groth16Verifier.sol (on-chain)"
echo "    keep build/pot_final.ptau; pin this as ceremony.phase1_ptau_sha256 for check-activation.ts --ptau:"
shasum -a 256 "$BUILD/pot_final.ptau"
