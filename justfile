# Run `just` to list the recipes. CI runs install, check-artifacts, check, test-ts
# and test-contracts, plus a dependency audit (.github/workflows/ci.yml).

default:
    @just --list

# Install the pinned npm packages.
install:
    npm ci

# What CI's test jobs run, in the same order.
test: check-artifacts check test-ts test-contracts

# Rebuild the circuit, dispatcher and verifier, and check them against the committed files.
check-artifacts:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(mktemp -d)
    node_modules/.bin/circom2 core/circuits/spend.circom --r1cs --wasm --sym -l node_modules -o "$out"
    node_modules/.bin/snarkjs r1cs info "$out/spend.r1cs"
    cmp "$out/spend.r1cs" core/artifacts/spend.r1cs
    cmp "$out/spend_js/spend.wasm" core/artifacts/spend_js/spend.wasm
    forge build --root core/contracts
    node tools/dispatcher.ts --artifact >/dev/null
    git diff --exit-code -- core/artifacts/shielded_pool_dispatcher_init.hex
    node tools/dispatcher.ts --initcode 0x0000000000000000000000000000000000000001 0x0000000000000000000000000000000000000002 >/dev/null
    # check-activation compares only the verifier's constants, so regenerate the whole
    # verifier from the proving key, as tools/setup.sh does, and require the committed file.
    node_modules/.bin/snarkjs zkey export solidityverifier core/artifacts/spend_final.zkey core/contracts/src/Groth16Verifier.sol >/dev/null
    node tools/patch-verifier.ts >/dev/null
    (cd core/contracts && forge fmt src/Groth16Verifier.sol >/dev/null)
    git diff --exit-code -- core/contracts/src/Groth16Verifier.sol

# Type-check and format-check the TypeScript, then the gas, activation and
# compiler-settings checks.
check:
    npx tsc -p .
    npx prettier --check .
    node tools/check-gas-profile.ts
    node tools/check-activation.ts core/activation_manifest.testbed.json --allow-testbed
    node tools/check-forge-config.ts core/activation_manifest.testbed.json core/contracts

# The TypeScript tests.
test-ts:
    node --test test/*.test.ts

# --force recompiles, so a cache left by an earlier build cannot shrink the suite.
# Format, lint and test the contracts.
test-contracts:
    forge fmt --root core/contracts --check
    forge lint --root core/contracts --deny warnings
    forge test --root core/contracts --force -vv

# The script lists the variables it needs (RPC_URL, a Foundry keystore and its
# password file, ALLOW_TESTBED_SETUP=1) and rewrites core/deploy_config.json.
# Deploy a fresh testbed pool, then shield, transfer and withdraw through it.
deploy:
    tools/run_live_dispatcher.sh

# The pinned files match only after the last step, forge fmt.
# Regenerate the Poseidon contracts from src/poseidon-constants.json.
poseidon:
    node tools/poseidon-sol.ts
    cd core/contracts && forge fmt src/PoseidonBN254.sol src/PoseidonT3.sol src/PoseidonT4.sol

# The ethrex path may be relative to the directory you run just from.
# Run real proofs through the pinned ethrex VM (see test/native/README.md).
native ethrex_source:
    node test/native/run.ts --ethrex-source "{{join(invocation_directory(), ethrex_source)}}"

# Report which formally verified files differ from the verified commit.
formal-pins:
    node tools/check-formal-pins.ts
