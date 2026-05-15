import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import Database from 'better-sqlite3';
import * as sqliteVec from 'sqlite-vec';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';

import { MnemoPayConfig, SecurityContext, Permission } from '../types/index';
import { NodeCrypto, PlatformCrypto } from '../security/crypto';
import { PermissionGuard, buildContext } from '../security/permissions';
import { RateLimiter } from '../security/rate-limiter';
import { FraudDetector } from '../security/fraud-detector';
import { MemoryStore } from '../memory/store';
import { WalletEngine } from '../payments/wallet';
import { SpatialProver } from '../gridstamp/spatial-prover';
import { EncryptedSync } from '../sync/encrypted-sync';
import { createAsyncEmbedder } from '../memory/embeddings';
import { NodeBridge, PlatformBridge } from '../platform/index';

export class MnemoPay {
  readonly db: Database.Database;
  private readonly crypto: PlatformCrypto;
  private readonly guard: PermissionGuard;
  private readonly rateLimiter: RateLimiter;
  private readonly fraud: FraudDetector;

  readonly memory: MemoryStore;
  readonly wallet: WalletEngine;
  readonly spatial: SpatialProver;
  readonly sync: EncryptedSync;

  private static _bridge: PlatformBridge = new NodeBridge();

  private constructor(
    private readonly config: MnemoPayConfig,
    ctx: SecurityContext,
    dbPath: string,
  ) {
    this.db = new Database(dbPath);
    sqliteVec.load(this.db);

    // WAL mode for concurrent reads
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    // Resolve the device-local DEK (data encryption key) once, then derive
    // per-purpose sub-keys via HKDF-SHA256. See _resolveDEK for the key-
    // management contract (explicit key > keystore file > dev-only opt-in).
    const dek = this._resolveDEK(config, dbPath);
    const encKey = config.encryptionKey ?? this._deriveSubKey(dek, 'mnemopay:enc:v1');
    const hmacKey = config.hmacKey ?? this._deriveSubKey(dek, 'mnemopay:mac:v1');
    const signingKey = config.signingKey ?? this._deriveSubKey(dek, 'mnemopay:sign:v1');
    this.crypto = new NodeCrypto(encKey, hmacKey, signingKey);
    this.guard = new PermissionGuard(ctx);

    const embedText = createAsyncEmbedder(config);

    // Init schemas BEFORE constructing security layer — FraudDetector and
    // RateLimiter hydrate persisted state on construction, so their tables
    // must exist first.
    MemoryStore.initSchema(this.db);
    WalletEngine.initSchema(this.db);
    SpatialProver.initSchema(this.db);
    FraudDetector.initSchema(this.db);
    RateLimiter.initSchema(this.db);

    if (config.disableRateLimitsForBenchmark) {
      console.warn('MnemoPay: disableRateLimitsForBenchmark is set — rate limits are OFF. FOR BENCHMARK/TEST USE ONLY.');
    }
    this.rateLimiter = new RateLimiter(this.db, { disabled: config.disableRateLimitsForBenchmark === true });
    this.fraud = new FraudDetector(this.db);

    this.memory = new MemoryStore(
      this.db, this.crypto, this.guard, this.rateLimiter, this.fraud, config, embedText,
    );

    this.wallet = new WalletEngine(
      this.db, this.crypto, this.guard, this.rateLimiter, this.fraud,
      config.agentId,
      BigInt(config.dailyLimitCents ?? 100_000),
    );

    this.spatial = new SpatialProver(
      this.db, this.crypto, this.guard, this.rateLimiter, this.fraud, config,
    );

    this.sync = new EncryptedSync(
      this.db, this.crypto, this.guard,
      config.agentId,
      config.deviceId ?? 'node-default',
      embedText,
    );
  }

  // ── Factory ───────────────────────────────────────────────────────────────
  static create(config: MnemoPayConfig, permissions?: Permission[]): MnemoPay {
    const perms: Permission[] = permissions ?? [
      'memory:read', 'memory:write', 'memory:delete',
      'wallet:read', 'wallet:send', 'wallet:escrow',
      'spatial:prove', 'spatial:verify',
      'sync:push', 'sync:pull',
    ];

    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(config.agentId)) {
      throw new Error(`Invalid agentId: must be 1-64 alphanumeric/dash/underscore characters`);
    }
    const ctx = buildContext(config.agentId, perms);
    const dbPath = MnemoPay._resolvePath(config);

    return new MnemoPay(config, ctx, dbPath);
  }

  // Register a hardware platform bridge (call before MnemoPay.create())
  static setPlatformBridge(bridge: PlatformBridge): void {
    MnemoPay._bridge = bridge;
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  // Call at the start of a conversation to inject relevant context.
  async sessionStart(userMessage: string): Promise<string> {
    return this.memory.autoRecall(userMessage);
  }

  // Call at the end of a conversation to persist salient facts.
  async sessionEnd(conversation: string, sessionId: string): Promise<void> {
    await this.memory.autoRetain(conversation, sessionId);
    this.memory.purgeExpired();
  }

  close(): void {
    this.db.close();
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  /**
   * Resolve the 32-byte Data Encryption Key (DEK) used as HKDF input.
   *
   * Contract (strongest → weakest):
   *   1. config.encryptionKey — caller passed an explicit key; pass through.
   *   2. Persistent random DEK file at `${dbDir}/.mnemopay.dek` (0o600).
   *      Generated on first run with crypto.randomBytes(32). This is the
   *      Node analog of storing a key in the platform keystore (Keychain /
   *      Keystore on mobile). Survives restarts, unique per install.
   *   3. Ephemeral deterministic fallback derived from agentId — ONLY
   *      allowed in non-production or when `allowInsecureDefault` is set.
   *
   * In production without an explicit key AND without a writable keystore
   * file, throws. Never silently falls back to deterministic keys in prod.
   */
  private _resolveDEK(config: MnemoPayConfig, dbPath: string): Uint8Array {
    if (config.encryptionKey) {
      return config.encryptionKey instanceof Uint8Array
        ? config.encryptionKey
        : new Uint8Array(Buffer.from(config.encryptionKey));
    }

    const keystorePath = path.join(path.dirname(dbPath), '.mnemopay.dek');
    try {
      if (fs.existsSync(keystorePath)) {
        const dek = fs.readFileSync(keystorePath);
        if (dek.length !== 32) {
          throw new Error(`Keystore file at ${keystorePath} is corrupt (expected 32 bytes, got ${dek.length})`);
        }
        return new Uint8Array(dek);
      }
      const dek = crypto.randomBytes(32);
      fs.writeFileSync(keystorePath, dek, { mode: 0o600, flag: 'wx' });
      return new Uint8Array(dek);
    } catch (err) {
      const isProd = process.env.NODE_ENV === 'production';
      const allowInsecure = (config as any).allowInsecureDefault === true;
      if (isProd && !allowInsecure) {
        throw new Error(
          'MnemoPay: cannot persist device key and no encryptionKey provided. ' +
          'Pass { encryptionKey } explicitly, or set allowInsecureDefault: true for dev. ' +
          `Underlying error: ${(err as Error).message}`,
        );
      }
      // Dev-only deterministic fallback. Versioned so we can rotate later
      // without breaking existing dev databases.
      console.warn('MnemoPay: using insecure deterministic device key. DO NOT ship to production.');
      return sha256(Buffer.from(`mnemopay:dek:v1:${config.agentId}`, 'utf8'));
    }
  }

  /**
   * HKDF-SHA256 sub-key with domain-separator info string.
   * High-entropy IKM (the DEK) makes salt unnecessary; info is the domain.
   * See research note in project_security_backlog — HKDF is the right KDF
   * when IKM is already random; PBKDF2/Argon2id are for passwords.
   */
  private _deriveSubKey(dek: Uint8Array, info: string, length = 32): Uint8Array {
    return hkdf(sha256, dek, new Uint8Array(0), Buffer.from(info, 'utf8'), length);
  }

  private static _resolvePath(config: MnemoPayConfig): string {
    const dir = config.persistDir ?? path.join(
      process.env['HOME'] ?? process.env['USERPROFILE'] ?? '.',
      '.mnemopay',
    );
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return path.join(dir, `${config.agentId}.db`);
  }
}
