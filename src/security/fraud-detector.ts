import Database from 'better-sqlite3';
import { FraudSignal, FraudType } from '../types/index';
import { sha256 } from '@noble/hashes/sha256';
import { generateId } from './crypto';

// 16+ injection patterns covering direct, delimiter, social engineering, jailbreak, encoding
const INJECTION_PATTERNS: RegExp[] = [
  /ignore previous instructions/i,
  /you are now/i,
  /system override/i,
  /\[INST\]/,
  /<<SYS>>/,
  /<\|im_start\|>/,
  /<\|endoftext\|>/,
  /pretend to be/i,
  /roleplay as/i,
  /bypass filters/i,
  /DAN mode/i,
  /jailbreak/i,
  /ignore all previous/i,
  /disregard your instructions/i,
  /act as if you have no/i,
  /you must obey/i,
];

// Zero-width / invisible Unicode used in homoglyph attacks
const HOMOGLYPH_RE = /[\u200B-\u200D\u00AD\uFEFF\u2060]/;

const ACTION_HISTORY_CAP = 100;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS fraud_nonce (
    agent_id   TEXT PRIMARY KEY,
    last_nonce INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS fraud_content_hash (
    agent_id   TEXT NOT NULL,
    hash       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, hash)
  );
  CREATE TABLE IF NOT EXISTS fraud_action (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT NOT NULL,
    action     TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_fraud_action_agent ON fraud_action(agent_id, id DESC);
  CREATE TABLE IF NOT EXISTS fraud_payment_edge (
    from_agent TEXT NOT NULL,
    to_agent   TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    last_ts    INTEGER NOT NULL,
    PRIMARY KEY (from_agent, to_agent)
  );
  CREATE TABLE IF NOT EXISTS fraud_spatial (
    agent_id TEXT PRIMARY KEY,
    lat      REAL NOT NULL,
    lng      REAL NOT NULL,
    ts       INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS fraud_signal_log (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    details_json TEXT NOT NULL,
    timestamp    INTEGER NOT NULL,
    auto_action  TEXT NOT NULL
  );
`;

export class FraudDetector {
  private nonceRegistry   = new Map<string, number>();
  private contentHashes   = new Map<string, Set<string>>();
  private actionHistory   = new Map<string, string[]>();
  private paymentGraph    = new Map<string, Map<string, { count: number; lastTs: number }>>();
  private spatialHistory  = new Map<string, { lat: number; lng: number; ts: number }>();
  private log: FraudSignal[] = [];

  constructor(private readonly db?: Database.Database) {
    if (db) this.hydrate(db);
  }

  static initSchema(db: Database.Database): void {
    db.exec(SCHEMA);
  }

  // Load persisted state into the write-through cache on construction.
  // Replay protection, collusion counts, and velocity checks depend on state
  // surviving process restarts — otherwise an attacker can bypass them by
  // forcing a crash loop.
  private hydrate(db: Database.Database): void {
    for (const row of db.prepare(`SELECT agent_id, last_nonce FROM fraud_nonce`).all() as any[]) {
      this.nonceRegistry.set(row.agent_id, row.last_nonce);
    }
    for (const row of db.prepare(`SELECT agent_id, hash FROM fraud_content_hash`).all() as any[]) {
      if (!this.contentHashes.has(row.agent_id)) this.contentHashes.set(row.agent_id, new Set());
      this.contentHashes.get(row.agent_id)!.add(row.hash);
    }
    for (const row of db.prepare(`SELECT from_agent, to_agent, count, last_ts FROM fraud_payment_edge`).all() as any[]) {
      if (!this.paymentGraph.has(row.from_agent)) this.paymentGraph.set(row.from_agent, new Map());
      this.paymentGraph.get(row.from_agent)!.set(row.to_agent, { count: row.count, lastTs: row.last_ts });
    }
    for (const row of db.prepare(`SELECT agent_id, lat, lng, ts FROM fraud_spatial`).all() as any[]) {
      this.spatialHistory.set(row.agent_id, { lat: row.lat, lng: row.lng, ts: row.ts });
    }
    // Action history — last N per agent, ordered oldest → newest for Sybil-style scans.
    const agents = db.prepare(`SELECT DISTINCT agent_id FROM fraud_action`).all() as any[];
    for (const { agent_id } of agents) {
      const rows = db.prepare(
        `SELECT action FROM fraud_action WHERE agent_id = ? ORDER BY id DESC LIMIT ?`,
      ).all(agent_id, ACTION_HISTORY_CAP) as any[];
      this.actionHistory.set(agent_id, rows.map(r => r.action).reverse());
    }
  }

  private emit(
    type: FraudType,
    severity: FraudSignal['severity'],
    agentId: string,
    details: Record<string, unknown>,
    autoAction: FraudSignal['autoAction'],
  ): FraudSignal {
    const sig: FraudSignal = { id: generateId('fraud'), type, severity, agentId, details, timestamp: Date.now(), autoAction };
    this.log.push(sig);
    if (this.db) {
      this.db.prepare(`
        INSERT INTO fraud_signal_log (id, type, severity, agent_id, details_json, timestamp, auto_action)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(sig.id, sig.type, sig.severity, sig.agentId, JSON.stringify(sig.details), sig.timestamp, sig.autoAction);
    }
    return sig;
  }

  // ── 5.1 Replay Attack ───────────────────────────────────────────────────────
  checkReplay(agentId: string, nonce: number): FraudSignal | null {
    const last = this.nonceRegistry.get(agentId) ?? -1;
    if (nonce <= last) {
      return this.emit('replay_attack', 'critical', agentId, { nonce, lastSeen: last }, 'reject');
    }
    this.nonceRegistry.set(agentId, nonce);
    if (this.db) {
      this.db.prepare(`
        INSERT INTO fraud_nonce (agent_id, last_nonce, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET last_nonce = excluded.last_nonce, updated_at = excluded.updated_at
      `).run(agentId, nonce, Date.now());
    }
    return null;
  }

  // ── 5.2 Prompt Injection ────────────────────────────────────────────────────
  checkInjection(content: string, agentId: string): FraudSignal | null {
    // Direct patterns
    for (const re of INJECTION_PATTERNS) {
      if (re.test(content)) {
        return this.emit('prompt_injection', 'high', agentId, { pattern: re.source }, 'reject');
      }
    }

    // Base64 decoding and re-check
    const b64Blocks = content.match(/[A-Za-z0-9+/]{20,}={0,2}/g) ?? [];
    for (const b64 of b64Blocks) {
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf8');
        for (const re of INJECTION_PATTERNS) {
          if (re.test(decoded)) {
            return this.emit('prompt_injection', 'high', agentId, { encoding: 'base64', pattern: re.source }, 'reject');
          }
        }
      } catch { /* not valid base64 */ }
    }

    // Hex encoding check
    const hexBlocks = content.match(/(?:0x)?[0-9a-fA-F]{20,}/g) ?? [];
    for (const hex of hexBlocks) {
      try {
        const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
        if (clean.length % 2 !== 0) continue;
        const decoded = Buffer.from(clean, 'hex').toString('utf8');
        for (const re of INJECTION_PATTERNS) {
          if (re.test(decoded)) {
            return this.emit('prompt_injection', 'high', agentId, { encoding: 'hex' }, 'reject');
          }
        }
      } catch { /* not valid hex */ }
    }

    // Unicode homoglyph smuggling
    if (HOMOGLYPH_RE.test(content)) {
      return this.emit('prompt_injection', 'medium', agentId, { encoding: 'unicode_homoglyph' }, 'reject');
    }

    return null;
  }

  // ── 5.3 Memory Poisoning ────────────────────────────────────────────────────
  checkPoisoning(
    content: string,
    agentId: string,
    importance: number,
  ): { signal: FraudSignal | null; clampedImportance: number } {
    let clampedImportance = importance;
    if (importance > 0.9) clampedImportance = 0.5;

    const hash = Buffer.from(sha256(Buffer.from(content, 'utf8'))).toString('hex');
    if (!this.contentHashes.has(agentId)) this.contentHashes.set(agentId, new Set());
    const hashes = this.contentHashes.get(agentId)!;
    if (hashes.has(hash)) {
      return {
        signal: this.emit('memory_poisoning', 'low', agentId, { reason: 'duplicate_content' }, 'log'),
        clampedImportance,
      };
    }
    hashes.add(hash);
    if (this.db) {
      this.db.prepare(`
        INSERT OR IGNORE INTO fraud_content_hash (agent_id, hash, created_at) VALUES (?, ?, ?)
      `).run(agentId, hash, Date.now());
    }
    return { signal: null, clampedImportance };
  }

  // ── 5.4 Spatial Spoofing ────────────────────────────────────────────────────
  checkSpatialSpoofing(
    agentId: string,
    accuracy: number,
    timestamp: number,
    confidence: number,
    isRooted: boolean,
  ): FraudSignal | null {
    if (isRooted) {
      return this.emit('spatial_spoofing', 'critical', agentId, { reason: 'rooted_device' }, 'reject');
    }
    const ageMs = Date.now() - timestamp;
    if (ageMs > 5 * 60 * 1000 || timestamp > Date.now() + 5000) {
      return this.emit('spatial_spoofing', 'critical', agentId, { reason: 'stale_timestamp', ageMs }, 'reject');
    }
    if (accuracy > 100) {
      return this.emit('spatial_spoofing', 'high', agentId, { reason: 'poor_gps_accuracy', accuracy }, 'reject');
    }
    if (confidence < 0.6) {
      return this.emit('spatial_spoofing', 'medium', agentId, { reason: 'low_scene_confidence', confidence }, 'throttle');
    }
    return null;
  }

  // ── 5.4b Velocity Check ─────────────────────────────────────────────────────
  checkVelocity(agentId: string, lat: number, lng: number, ts: number): FraudSignal | null {
    const last = this.spatialHistory.get(agentId);
    this.spatialHistory.set(agentId, { lat, lng, ts });
    if (this.db) {
      this.db.prepare(`
        INSERT INTO fraud_spatial (agent_id, lat, lng, ts) VALUES (?, ?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET lat = excluded.lat, lng = excluded.lng, ts = excluded.ts
      `).run(agentId, lat, lng, ts);
    }

    if (!last) return null;

    const dtSec = (ts - last.ts) / 1000;
    if (dtSec <= 0) return null;

    const R = 6_371_000;
    const dLat = ((lat - last.lat) * Math.PI) / 180;
    const dLng = ((lng - last.lng) * Math.PI) / 180;
    const a =
      Math.sin(dLat / 2) ** 2 +
      Math.cos((last.lat * Math.PI) / 180) * Math.cos((lat * Math.PI) / 180) * Math.sin(dLng / 2) ** 2;
    const distM = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    const speedMs = distM / dtSec;
    if (speedMs > 340) {
      return this.emit('spatial_spoofing', 'critical', agentId, { reason: 'impossible_velocity', speedMs, distM, dtSec }, 'reject');
    }
    return null;
  }

  // ── 5.5 Collusion Detection ─────────────────────────────────────────────────
  checkCollusion(fromAgent: string, toAgent: string): FraudSignal | null {
    if (!this.paymentGraph.has(fromAgent)) this.paymentGraph.set(fromAgent, new Map());
    const edges = this.paymentGraph.get(fromAgent)!;
    const edge = edges.get(toAgent) ?? { count: 0, lastTs: 0 };
    edge.count += 1;
    edge.lastTs = Date.now();
    edges.set(toAgent, edge);
    if (this.db) {
      this.db.prepare(`
        INSERT INTO fraud_payment_edge (from_agent, to_agent, count, last_ts) VALUES (?, ?, ?, ?)
        ON CONFLICT(from_agent, to_agent) DO UPDATE SET count = excluded.count, last_ts = excluded.last_ts
      `).run(fromAgent, toAgent, edge.count, edge.lastTs);
    }

    const reverse = this.paymentGraph.get(toAgent)?.get(fromAgent);
    if (edge.count >= 3 && reverse && reverse.count >= 3) {
      return this.emit('collusion_pattern', 'high', fromAgent, { toAgent, fwdCount: edge.count, revCount: reverse.count }, 'freeze');
    }
    return null;
  }

  // ── 5.6 Sybil Detection ─────────────────────────────────────────────────────
  recordAction(agentId: string, action: string): void {
    if (!this.actionHistory.has(agentId)) this.actionHistory.set(agentId, []);
    const hist = this.actionHistory.get(agentId)!;
    hist.push(action);
    if (hist.length > ACTION_HISTORY_CAP) hist.shift();

    if (this.db) {
      const ts = Date.now();
      this.db.transaction(() => {
        this.db!.prepare(`INSERT INTO fraud_action (agent_id, action, created_at) VALUES (?, ?, ?)`)
          .run(agentId, action, ts);
        // Trim DB to the same cap so long-running agents don't grow the table unbounded.
        this.db!.prepare(`
          DELETE FROM fraud_action
          WHERE agent_id = ?
            AND id NOT IN (SELECT id FROM fraud_action WHERE agent_id = ? ORDER BY id DESC LIMIT ?)
        `).run(agentId, agentId, ACTION_HISTORY_CAP);
      })();
    }
  }

  getLog(): FraudSignal[] { return [...this.log]; }
  clearLog(): void {
    this.log = [];
    if (this.db) this.db.prepare(`DELETE FROM fraud_signal_log`).run();
  }
}
