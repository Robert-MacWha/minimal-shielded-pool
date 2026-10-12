/**
 * Gas limits shared by the pool builder and its checks.
 *
 * This profile follows EIP-8250 PR 12279 (keyed-nonce first use as state gas) and EIP-8272 at
 * 824cbc0b0e (PRs 12281 and 12302): the recent root travels in a canonical VERIFY frame that
 * leads the transaction, and that frame's execution budget counts toward the public mempool's
 * verify budget.
 *
 * The activation manifest pins this file's bytes, so it imports nothing and holds only
 * constants. Gas amounts are bigint and byte lengths are number, except
 * STATE_BYTES_PER_STORAGE_SET, which only multiplies the per-byte state gas price CPSB.
 */

// Wallet defaults for the two validation frames. The dispatcher does not pin them: a limit
// that is too low only makes the transaction invalid, and the proof fee covers whatever is
// declared, so wallets can raise them after a repricing without a new pool. The recent-root
// frame (cold access to the predeploy, two keccaks, one cold SLOAD over one 72-byte tuple)
// used 5,579. With hybrid public-input compression and the owner's intent digest the proof
// frame uses 210,659, plus 90 with a fourth frame and 27 when nf1 > nf2, and the heaviest
// spend needs a limit of 216,751 because each nested call keeps back 1/64 of its gas. The
// defaults leave about 2,400 and 8,250 gas of headroom, so with the two signatures the
// declared validation budget is 238,600.
export const RECENT_ROOT_FRAME_GAS = 8_000n;
export const RECENT_ROOT_TUPLE_BYTES = 72;
// owner-set-v1 commits each note to an owner set and adds the owner's signature to every
// spend, so its notes, proofs and transactions are not compatible with position-notes-v3.
export const POOL_PROFILE = "owner-set-v1";
// The previous profile. Between a profile change and its first deployment the deployment
// record still names it, and the CLI refuses to spend against it.
export const PREVIOUS_POOL_PROFILE = "position-notes-v3";
// A note is a 16-byte tag, a 16-byte encrypted amount and a 16-byte authentication tag
// (src/notes.ts). Settlement calldata is settle(Spend) followed by two notes, and a
// sender's first payment to a public address puts its ML-KEM-768 ciphertext before them.
// A shield carries one note, optionally after a ciphertext.
export const NOTE_BYTES = 48;
export const KEM_CIPHERTEXT_BYTES = 1088;
export const SETTLE_SPEND_BYTES = 4 + 12 * 32;
export const SPEND_NOTES_BYTES: readonly number[] = Object.freeze([
  2 * NOTE_BYTES,
  KEM_CIPHERTEXT_BYTES + 2 * NOTE_BYTES,
]);
export const SHIELD_NOTE_BYTES: readonly number[] = Object.freeze([
  NOTE_BYTES,
  KEM_CIPHERTEXT_BYTES + NOTE_BYTES,
]);
export const SETTLE_FRAME_DATA_BYTES: readonly number[] = Object.freeze(
  SPEND_NOTES_BYTES.map((n) => SETTLE_SPEND_BYTES + n),
);
export const VERIFY_FRAME_GAS = 225_000n;
// Native ethrex 247e2dd2 spends at 262,143 and 524,287 leaves verify and
// approve, then settlement OOGs with no outputs at 1.4M. The signed SENDER
// pin is 2M so EIP-150 forwarding still covers that long-carry. 2M is the
// reproduced fix, not a proof of every settlement shape. State stays a
// separate declared dimension.
export const SETTLE_FRAME_GAS = 2_000_000n;
export const SETTLE_FRAME_STATE_GAS = 550_000n;
// Wallet/tooling default for the normal withdraw tail:
// DEFAULT(pool, claimWithdrawal(recipient)). These used to be dispatcher
// pins. The fourth frame is optional on every spend; omitting it on a
// withdrawal leaves withdrawalCredit. These remain the declared limits
// when the wallet does emit the default claim. Custom tails declare their
// own budgets inside remaining transaction capacity. On native ethrex
// commit 247e2dd2, a DEFAULT claim to a new EOA used 14,716 execution gas
// and 183,600 state gas.
export const CLAIM_FRAME_GAS = 100_000n;
export const CLAIM_FRAME_STATE_GAS = 183_600n;
// EIP-7825 per-transaction execution cap. State gas is a separate declared
// dimension and is not charged against this number. Native testing admitted
// 10M execution plus 10M state on a spend that still left room for verify
// and settlement.
export const EIP7825_TX_GAS_CAP = 1n << 24n;
// Pinned ethrex mempool policy for the entire encoded FrameTx, not the tail.
export const ETHREX_MEMPOOL_MAX_BYTES = 128 * 1024;

export const STATE_BYTES_PER_STORAGE_SET = 64n;
export const CPSB = 1_530n;
export const SPEND_NONCE_KEY_COUNT = 2n;
export const KEYED_NONCE_FIRST_USE_STATE_GAS = STATE_BYTES_PER_STORAGE_SET * CPSB;
export const VERIFY_FRAME_STATE_GAS = SPEND_NONCE_KEY_COUNT * KEYED_NONCE_FIRST_USE_STATE_GAS;

// The public mempool budgets the two prefix frames and the signatures together. A spend has
// two secp256k1 signatures, the authorizer's and the owner's. The Hegotá testnet admits up to
// 500,000 (`--mempool.max-verify-gas`); EIP-8141's published default is 100,000, which this
// profile has never fit.
export const SIGNATURE_GAS = 2_800n;
export const SPEND_SIGNATURES = 2n;
export const REQUIRED_VERIFY_BUDGET =
  RECENT_ROOT_FRAME_GAS + VERIFY_FRAME_GAS + SPEND_SIGNATURES * SIGNATURE_GAS;
export const HEGOTA_TESTNET_MAX_VERIFY_GAS = 500_000n;
// EIP-8141 `MAX_VERIFY_STATE_GAS`: the prefix frames' state budgets together.
export const MAX_VERIFY_STATE_GAS = 500_000n;
