# Changelog

## 0.1.3 — Persistent fraud + rate-limit state

- `FraudDetector` and `RateLimiter` now persist to SQLite by default when the SDK is constructed through `MnemoPay.create`. Replay nonces, collusion edge counts, duplicate-content hashes, velocity history, action logs, rate-limit windows, and fraud signal logs all survive process restarts. Previously each restart zeroed the state and turned replay, rate-limit, and collusion checks into trivial bypasses. Both classes still run in-memory-only when instantiated without a `Database` handle (no back-compat break for embedding code).
- Added `tests/persistence.test.ts` covering the three critical round-trips: replay rejection after restart, collusion trip after restart, rate-limit window carry-over across restart.

## 0.1.2 — Internal hardening

- Strengthened device-local key management. The per-install Data Encryption Key is now a random 32-byte value persisted at `.mnemopay.dek` (0o600) inside the SDK's data directory, with HKDF-SHA256 sub-keys for encryption, MAC, and signing. Production builds without an explicit `encryptionKey` and without a writable keystore fail closed rather than falling back to a deterministic default. A dev-only `allowInsecureDefault` opt-in preserves the old behavior for unit tests and read-only filesystems.
- Collapsed escrow `settle()` validation and state mutation into a single write-locked transaction (`BEGIN IMMEDIATE`), eliminating a TOCTOU window where two concurrent settle calls could both pass the active-status check before either entered the transaction.
- Stopped leaking sync blob identifiers in error logs when running under `NODE_ENV=production`.
- Expanded `.gitignore` to exclude test SQLite databases, `tmp-*/` dirs, build artifacts, and local secrets.

### Known issues

- In-memory fraud-detector and rate-limiter state still resets on restart. Persistence work is scheduled for 0.2.0.
