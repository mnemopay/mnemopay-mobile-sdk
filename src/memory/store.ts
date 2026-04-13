import Database from 'better-sqlite3';
import * as sqliteVec from 'sqlite-vec';
import { sha256 } from '@noble/hashes/sha256'; // Keep sha256 for integrity check
import {
  Memory, MemoryMetadata, MemoryQuery, MemoryRecallResult, MnemoPayConfig,
  DecayCurveMode, BlendPreset,
} from '../types/index';
import { PlatformCrypto, generateId } from '../security/crypto';
import { PermissionGuard, SecurityError } from '../security/permissions';
import { RateLimiter } from '../security/rate-limiter';
import { FraudDetector } from '../security/fraud-detector';
import { classifyQuery, BLEND_PRESETS } from './queryClassifier';

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS memories (
    id               TEXT    PRIMARY KEY,
    content_enc      BLOB    NOT NULL,
    metadata_enc     BLOB    NOT NULL,
    integrity_mac    BLOB    NOT NULL,
    importance       REAL    NOT NULL DEFAULT 0.5,
    access_count     INTEGER NOT NULL DEFAULT 0,
    decay_score      REAL    NOT NULL DEFAULT 1.0,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    expires_at       INTEGER,
    agent_id         TEXT    NOT NULL,
    session_id       TEXT    NOT NULL,
    permanent        INTEGER NOT NULL DEFAULT 0
  );

  CREATE VIRTUAL TABLE IF NOT EXISTS memory_vectors USING vec0(
    id        TEXT PRIMARY KEY,
    agent_id  TEXT PARTITION KEY,
    embedding FLOAT[384]
  );

  CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(id, content, tokenize='porter');

  CREATE TABLE IF NOT EXISTS sync_log (
    id         TEXT    PRIMARY KEY,
    table_name TEXT    NOT NULL,
    record_id  TEXT    NOT NULL,
    synced     INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS store_config (
    key   TEXT PRIMARY KEY,
    value BLOB
  );
`;

export class MemoryStore {
  private readonly agentId: string;
  private readonly halfLifeMs: number;
  private readonly memoryCap: number;
  private readonly embeddingDim: number;
  private readonly embedText: (text: string) => Promise<Float32Array>;
  private readonly vectorKMultiplier: number;
  private readonly candidateLimit: number;
  private readonly decayCurve: DecayCurveMode;

  constructor(
    private readonly db: Database.Database,
    private readonly crypto: PlatformCrypto,
    private readonly guard: PermissionGuard,
    private readonly rateLimiter: RateLimiter,
    private readonly fraud: FraudDetector,
    config: MnemoPayConfig,
    embedText: (text: string) => Promise<Float32Array>,
  ) {
    this.agentId = config.agentId;
    this.halfLifeMs = (config.memoryHalfLifeDays ?? 7) * 86_400_000;
    this.memoryCap = config.memoryCapacity ?? 10_000;
    this.embeddingDim = config.embeddingDimensions ?? 384;
    this.embedText = embedText;
    this.vectorKMultiplier = Math.max(1, Math.floor(config.vectorKMultiplier ?? 3));
    this.candidateLimit = config.candidateLimit ?? 50;
    this.decayCurve = config.decayCurve ?? 'logarithmic';
  }

  static loadExtensions(db: Database.Database): void {
    sqliteVec.load(db);
  }

  static initSchema(db: Database.Database): void {
    db.exec(SCHEMA);
  }

  private calculateDecay(createdAt: number, mode: DecayCurveMode, boostDecay = false): number {
    if (mode === 'none') return 1.0;

    const ageMs = Date.now() - createdAt;
    const ageDays = ageMs / 86_400_000;
    const maxAgeDays = (this.halfLifeMs * 10) / 86_400_000; // heuristic limit
    
    let factor = 1.0;
    switch (mode) {
      case 'linear':
        factor = Math.max(0, 1 - (ageDays / maxAgeDays));
        break;
      case 'exponential':
        const lambda = boostDecay ? 0.1 : 0.05;
        factor = Math.exp(-lambda * ageDays);
        break;
      case 'logarithmic':
        factor = Math.max(0, 1 - (Math.log(1 + ageDays) / Math.log(1 + maxAgeDays)));
        break;
    }
    return factor;
  }

  // Sanitizes query text for FTS5 to handle special characters and boolean operators
  private sanitizeFtsQuery(text: string): string {
    return text
      .replace(/[^\p{L}\p{N}\s]/gu, ' ') // Replace non-alphanumeric with space
      .split(/\s+/) // Split by whitespace
      .filter(token => token.length > 0) // Remove empty tokens
      .map(token => {
        // If it's a number, it's likely a specific ID/index, prioritize it
        if (/^\d+$/.test(token)) return `"${token}"`;
        // For words, use prefix wildcard for flexibility but wrap in quotes for exactness
        return token.length > 3 ? `"${token}" OR "${token}*"` : `"${token}"`;
      })
      .join(' OR '); // Combine with OR for broad matching
  }

  // ── retain ──────────────────────────────────────────────────────────────────
  async retain(
    content: string,
    metadata: Omit<MemoryMetadata, 'agentId'>,
  ): Promise<Memory> {
    this.guard.enforce('memory:write');

    const { allowed } = this.rateLimiter.check(this.agentId, 'memory_write');
    if (!allowed) {
      throw new SecurityError('RATE_LIMITED', 'Memory write rate limit exceeded');
    }

    // Injection check
    const injSig = this.fraud.checkInjection(content, this.agentId);
    if (injSig) throw new SecurityError('FRAUD_DETECTED', `Prompt injection blocked: ${injSig.details.pattern ?? injSig.details.encoding}`);

    // Poisoning / importance clamp
    const { signal: poisonSig, clampedImportance } = this.fraud.checkPoisoning(content, this.agentId, metadata.importance);
    if (poisonSig?.autoAction === 'reject') throw new SecurityError('FRAUD_DETECTED', 'Memory poisoning detected');

    const fullMeta: MemoryMetadata = { ...metadata, agentId: this.agentId, importance: clampedImportance };
    const id = generateId('mem');
    const now = Date.now();
    const embedding = await this.embedText(content);

    // Integrity HMAC over canonical representation
    const integrityInput = Buffer.from(JSON.stringify({
      id,
      content,
      metadata: {
        source: fullMeta.source,
        sessionId: fullMeta.sessionId,
        agentId: fullMeta.agentId,
        tags: fullMeta.tags,
        importance: fullMeta.importance,
        ttl: fullMeta.ttl,
      }
    }), 'utf8');
    const integrityMac = await this.crypto.hmac(integrityInput);

    // Encrypt content and metadata separately
    const encContent = await this.crypto.encrypt(Buffer.from(content, 'utf8'));
    const encMeta = await this.crypto.encrypt(Buffer.from(JSON.stringify(fullMeta), 'utf8'));

    const isPermanent = metadata.permanent ? 1 : 0;

    this.db.transaction(() => {
      this.db.prepare(`
        INSERT INTO memories
          (id, content_enc, metadata_enc, integrity_mac, importance, access_count,
           decay_score, created_at, updated_at, expires_at, agent_id, session_id, permanent)
        VALUES (?, ?, ?, ?, ?, 0, 1.0, ?, ?, ?, ?, ?, ?)
      `).run(
        id, encContent, encMeta, integrityMac,
        clampedImportance, now, now,
        fullMeta.ttl ? now + fullMeta.ttl : null,
        this.agentId, fullMeta.sessionId, isPermanent
      );

      this.db.prepare(`INSERT INTO memory_vectors (id, agent_id, embedding) VALUES (?, ?, ?)`)
        .run(id, this.agentId, new Uint8Array(embedding.buffer, embedding.byteOffset, embedding.byteLength));

      this.db.prepare(`INSERT INTO memories_fts (id, content) VALUES (?, ?)`).run(id, content);
      // Track for sync
      this.db.prepare(`
        INSERT OR REPLACE INTO sync_log (id, table_name, record_id, synced, updated_at)
        VALUES (?, 'memories', ?, 0, ?)
      `).run(generateId('sl'), id, now);
    })();

    this.evictIfNeeded();

    return {
      id, content, embedding, metadata: fullMeta,
      createdAt: now, updatedAt: now, accessCount: 0,
      decayScore: 1.0, integrity: Buffer.from(integrityMac).toString('hex'),
      permanent: !!metadata.permanent,
    };
  }

  // ── recall ──────────────────────────────────────────────────────────────────
  async recall(query: MemoryQuery): Promise<MemoryRecallResult[]> {
    this.guard.enforce('memory:read');
    this.rateLimiter.check(this.agentId, 'general');

    const queryVec = query.embedding ?? (query.text ? await this.embedText(query.text) : null);
    if (!queryVec && !query.text) return [];

    const limit = query.limit ?? 10;
    const candidateLimit = this.candidateLimit;

    // 0. Query Classification
    let blendWeight = 0.8;
    let boostDecay = false;

    if (query.noveltyMode) {
      blendWeight = 1.0; // Strict semantic-only matching for novelty checks
    } else if (query.text) {
      const classification = classifyQuery(query.text);
      blendWeight = classification.recommendedBlend;
      boostDecay = classification.boostDecay ?? false;
    }

    // Override with explicit blendRatio if provided
    if (query.blendRatio !== undefined && !query.noveltyMode) {
      if (typeof query.blendRatio === 'string') {
        blendWeight = BLEND_PRESETS[query.blendRatio];
      } else {
        blendWeight = query.blendRatio;
      }
    }

    const ftsWeight = 1.0 - blendWeight;

    // 1. Collect FTS candidates
    const ftsScores = new Map<string, number>();
    if (query.text && !query.noveltyMode) {
      const sanitizedQuery = this.sanitizeFtsQuery(query.text);
      if (sanitizedQuery.length > 0) {
        const ftsMatches = this.db.prepare(`
          SELECT id, rank 
          FROM memories_fts 
          WHERE content MATCH ? 
          ORDER BY rank 
          LIMIT ?
        `).all(sanitizedQuery, candidateLimit) as { id: string; rank: number }[];
        
        ftsMatches.forEach((m, i) => {
          ftsScores.set(m.id, 1.0 / (i + 1));
        });
      }
    }

    // 2. Collect Vector candidates
    const vecResults = new Map<string, number>();
    if (queryVec) {
      const rows = this.db.prepare(`
        SELECT mv.id, mv.distance
        FROM memory_vectors mv
        WHERE mv.embedding MATCH ?
          AND k = ?
          AND mv.agent_id = ?
        ORDER BY mv.distance
      `).all(
        new Uint8Array(queryVec.buffer, queryVec.byteOffset, queryVec.byteLength),
        candidateLimit,
        this.agentId,
      ) as { id: string; distance: number }[];

      rows.forEach(r => vecResults.set(r.id, r.distance));
    }

    // 3. Union of candidates
    const candidateIds = Array.from(new Set([...ftsScores.keys(), ...vecResults.keys()]));
    if (candidateIds.length === 0) return [];

    // 4. Fetch full rows and rerank
    const placeholders = candidateIds.map(() => '?').join(',');
    const rows = this.db.prepare(`
      SELECT * FROM memories 
      WHERE id IN (${placeholders})
        AND agent_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
    `).all(...candidateIds, this.agentId, Date.now()) as any[];

    const results: MemoryRecallResult[] = [];

    for (const row of rows) {
      try {
        const content = Buffer.from(await this.crypto.decrypt(Buffer.from(row.content_enc))).toString('utf8');
        const metadata: MemoryMetadata = JSON.parse(
          Buffer.from(await this.crypto.decrypt(Buffer.from(row.metadata_enc))).toString('utf8'),
        );

        const integrityInput = Buffer.from(JSON.stringify({
          id: row.id, content,
          metadata: {
            source: metadata.source, sessionId: metadata.sessionId, agentId: metadata.agentId,
            tags: metadata.tags, importance: metadata.importance, ttl: metadata.ttl,
          }
        }), 'utf8');
        const valid = await this.crypto.verifyHmac(integrityInput, Buffer.from(row.integrity_mac));
        if (!valid) continue;

        // Post-filters
        if (query.sessionId && metadata.sessionId !== query.sessionId) continue;
        if (query.agentId && metadata.agentId !== query.agentId) continue;
        if (query.tags?.length && !query.tags.some(t => metadata.tags.includes(t))) continue;
        if (query.minImportance != null && metadata.importance < query.minImportance) continue;

        const distance = vecResults.get(row.id) ?? 1.0;
        const ftsScore = ftsScores.get(row.id) ?? 0.0;
        
        const cosine = 1 - (distance / 2);
        if (query.threshold != null && cosine < query.threshold && ftsScore === 0) continue;

        // Combined Score: Higher weight to FTS (0.4) for precise matching in hybrid scenarios
        // if no explicit blendRatio is provided.
        const effectiveBlend = (query.blendRatio === undefined && ftsScore > 0) ? 0.6 : blendWeight;
        const effectiveFtsWeight = 1.0 - effectiveBlend;

        const hybridScore = (cosine * effectiveBlend) + (ftsScore * effectiveFtsWeight);
        
        const decayFactor = (row.permanent === 1) ? 1.0 : this.calculateDecay(row.created_at, this.decayCurve, boostDecay);

        const finalScore = hybridScore
          * decayFactor
          * (1 + 0.05 * Math.log2(row.access_count + 1))
          * metadata.importance;

        results.push({
          memory: {
            id: row.id, content, embedding: queryVec ?? new Float32Array(), metadata,
            createdAt: row.created_at, updatedAt: row.updated_at,
            accessCount: row.access_count, decayScore: finalScore,
            integrity: Buffer.from(row.integrity_mac).toString('hex'),
            permanent: row.permanent === 1,
          },
          score: finalScore,
          distance,
        });
      } catch {
        continue;
      }
    }

    const finalTopK = results.sort((a, b) => b.score - a.score).slice(0, limit);
    for (const res of finalTopK) {
      this.db.prepare(`UPDATE memories SET access_count = access_count + 1, updated_at = ? WHERE id = ?`)
        .run(Date.now(), res.memory.id);
    }

    return finalTopK;
  }

  // ── forget ───────────────────────────────────────────────────────────────────
  async forget(memoryId: string): Promise<void> {
    this.guard.enforce('memory:delete');
    this.db.transaction(() => {
      this.db.prepare(`
        UPDATE memories
        SET content_enc = zeroblob(length(content_enc)),
            metadata_enc = zeroblob(length(metadata_enc))
        WHERE id = ? AND agent_id = ?
      `).run(memoryId, this.agentId);

      this.db.prepare(`DELETE FROM memories WHERE id = ? AND agent_id = ?`).run(memoryId, this.agentId);
      this.db.prepare(`DELETE FROM memory_vectors WHERE id = ? AND agent_id = ?`).run(memoryId, this.agentId);
      this.db.prepare(`DELETE FROM memories_fts WHERE id = ?`).run(memoryId);
    })();
  }

  // ── autoRecall — LLM context injection ──────────────────────────────────────
  async autoRecall(userMessage: string, tokenBudget = 1500): Promise<string> {
    const results = await this.recall({ text: userMessage, limit: 10, threshold: 0.3 });
    if (results.length === 0) return '';

    let ctx = '[Relevant memory context]\n';
    let tokenCount = 10;

    for (const r of results) {
      const ts = new Date(r.memory.createdAt).toISOString().slice(0, 16);
      const line = `[${ts}] (rel:${r.score.toFixed(2)}) ${r.memory.content}\n`;
      const est = Math.ceil(line.length / 4);
      if (tokenCount + est > tokenBudget) break;
      ctx += line;
      tokenCount += est;
    }

    return ctx;
  }

  // ── autoRetain — salient fact extraction from conversation ───────────────────
  async autoRetain(conversation: string, sessionId: string): Promise<Memory[]> {
    const sentences = conversation
      .split(/(?<=[.!])\s+/)
      .map(s => s.trim())
      .filter(s => {
        if (s.length < 20) return false;
        if (/^(hi|hello|hey|ok|okay|thanks|sure|yes|no)\b/i.test(s)) return false;
        if (s.endsWith('?')) return false;
        return true;
      })
      .slice(0, 5);

    const stored: Memory[] = [];

    for (const sentence of sentences) {
      try {
        const existing = await this.recall({ text: sentence, limit: 1, threshold: 0.92, noveltyMode: true });
        if (existing.length > 0) continue;

        const mem = await this.retain(sentence, {
          source: 'conversation',
          sessionId,
          tags: ['auto'],
          importance: 0.5,
        });
        stored.push(mem);
      } catch {
        break;
      }
    }

    return stored;
  }

  // ── Maintenance ──────────────────────────────────────────────────────────────
  purgeExpired(): void {
    const expired = this.db.prepare(
      `SELECT id FROM memories WHERE expires_at IS NOT NULL AND expires_at <= ? AND agent_id = ?`,
    ).all(Date.now(), this.agentId) as { id: string }[];
    for (const row of expired) this.forget(row.id);
  }

  private evictIfNeeded(): void {
    const count = (this.db.prepare(
      `SELECT COUNT(*) as c FROM memories WHERE agent_id = ?`,
    ).get(this.agentId) as any).c;

    if (count > this.memoryCap) {
      const row = this.db.prepare(`
        SELECT id FROM memories WHERE agent_id = ?
        ORDER BY (importance * decay_score) ASC LIMIT 1
      `).get(this.agentId) as { id: string } | undefined;
      if (row) this.forget(row.id);
    }
  }

  count(): number {
    return (this.db.prepare(`SELECT COUNT(*) as c FROM memories WHERE agent_id = ?`).get(this.agentId) as any).c;
  }
}
