import Database from 'better-sqlite3';
import { FraudSignal } from '../types/index';
import { generateId } from './crypto';

type Category = 'general' | 'memory_write' | 'transaction' | 'spatial';

const LIMITS: Record<Category, { count: number; windowMs: number }> = {
  general:      { count: 60,  windowMs: 60_000 },
  memory_write: { count: 200, windowMs: 3_600_000 },
  transaction:  { count: 50,  windowMs: 3_600_000 },
  spatial:      { count: 30,  windowMs: 3_600_000 },
};

const BURST_MAX = 10;
const BURST_REFILL_PER_SEC = 1;

interface Window {
  timestamps: number[];
  burstTokens: number;
  lastRefill: number;
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS rate_limit_window (
    agent_id        TEXT NOT NULL,
    category        TEXT NOT NULL,
    timestamps_json TEXT NOT NULL,
    burst_tokens    REAL NOT NULL,
    last_refill     INTEGER NOT NULL,
    PRIMARY KEY (agent_id, category)
  );
`;

/**
 * FOR TEST / BENCHMARK USE ONLY — pass `{ disabled: true }` to skip all
 * rate-limit checks. This option MUST NOT be set in production code.
 * Production LIMITS constants are unchanged; the bypass is opt-in at
 * construction time only and has no env-var equivalent.
 */
export interface RateLimiterOptions {
  disabled?: boolean;
}

export class RateLimiter {
  private state = new Map<string, Map<Category, Window>>();
  private readonly disabled: boolean;

  constructor(private readonly db?: Database.Database, opts: RateLimiterOptions = {}) {
    this.disabled = opts.disabled === true;
    if (db) this.hydrate(db);
  }

  static initSchema(db: Database.Database): void {
    db.exec(SCHEMA);
  }

  // On boot, restore per-agent windows so a restart doesn't reset a throttled
  // attacker's counter back to zero. Stale windows (outside the widest window)
  // are naturally pruned on the next check() call by the slide step.
  private hydrate(db: Database.Database): void {
    const rows = db.prepare(`SELECT agent_id, category, timestamps_json, burst_tokens, last_refill FROM rate_limit_window`).all() as any[];
    for (const row of rows) {
      if (!this.state.has(row.agent_id)) this.state.set(row.agent_id, new Map());
      try {
        const timestamps: number[] = JSON.parse(row.timestamps_json);
        this.state.get(row.agent_id)!.set(row.category as Category, {
          timestamps,
          burstTokens: row.burst_tokens,
          lastRefill: row.last_refill,
        });
      } catch { /* corrupt row — skip; slide will rebuild fresh */ }
    }
  }

  private persist(agentId: string, cat: Category, w: Window): void {
    if (!this.db) return;
    this.db.prepare(`
      INSERT INTO rate_limit_window (agent_id, category, timestamps_json, burst_tokens, last_refill)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(agent_id, category) DO UPDATE SET
        timestamps_json = excluded.timestamps_json,
        burst_tokens    = excluded.burst_tokens,
        last_refill     = excluded.last_refill
    `).run(agentId, cat, JSON.stringify(w.timestamps), w.burstTokens, w.lastRefill);
  }

  private getWindow(agentId: string, cat: Category): Window {
    if (!this.state.has(agentId)) this.state.set(agentId, new Map());
    const agent = this.state.get(agentId)!;
    if (!agent.has(cat)) {
      agent.set(cat, { timestamps: [], burstTokens: BURST_MAX, lastRefill: Date.now() });
    }
    return agent.get(cat)!;
  }

  private refill(w: Window): void {
    const elapsed = (Date.now() - w.lastRefill) / 1000;
    w.burstTokens = Math.min(BURST_MAX, w.burstTokens + elapsed * BURST_REFILL_PER_SEC);
    w.lastRefill = Date.now();
  }

  check(agentId: string, cat: Category): { allowed: boolean; signal: FraudSignal | null } {
    if (this.disabled) return { allowed: true, signal: null };

    const limit = LIMITS[cat];
    const w = this.getWindow(agentId, cat);
    const now = Date.now();

    w.timestamps = w.timestamps.filter(t => now - t < limit.windowMs);

    if (w.timestamps.length < limit.count) {
      w.timestamps.push(now);
      this.persist(agentId, cat, w);
      return { allowed: true, signal: null };
    }

    this.refill(w);
    if (w.burstTokens >= 1) {
      w.burstTokens -= 1;
      w.timestamps.push(now);
      this.persist(agentId, cat, w);
      return { allowed: true, signal: null };
    }

    // Still persist the slide + refill bookkeeping so the DB reflects current state.
    this.persist(agentId, cat, w);

    const signal: FraudSignal = {
      id: generateId('rate'),
      type: 'velocity_spike',
      severity: 'medium',
      agentId,
      details: { category: cat, windowMs: limit.windowMs, count: w.timestamps.length },
      timestamp: now,
      autoAction: 'throttle',
    };
    return { allowed: false, signal };
  }

  reset(agentId: string): void {
    this.state.delete(agentId);
    if (this.db) {
      this.db.prepare(`DELETE FROM rate_limit_window WHERE agent_id = ?`).run(agentId);
    }
  }
}
