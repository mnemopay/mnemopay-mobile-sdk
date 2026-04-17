/**
 * LongMem eval — long-term memory scale + recall quality (exact vs paraphrase).
 *
 * Run:
 *   npm run eval:longmem
 *   LONGMEM_N=1000 npm run eval:longmem
 *   LONGMEM_N=5000 LONGMEM_SAMPLES=80 LONGMEM_RECALL_LIMIT=60 npm run eval:longmem
 *   LONGMEM_EMBEDDINGS=semantic npm run eval:longmem   # Xenova MiniLM (needs @xenova/transformers)
 */
import { MnemoPay } from '../../src/index';
import { classifyQuery } from '../../src/memory/queryClassifier';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BENCH_DIR = path.join(__dirname, 'tmp-longmem');

function parseEnvInt(name: string, defaultVal: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return defaultVal;
  const v = parseInt(raw, 10);
  return Number.isFinite(v) && v > 0 ? v : defaultVal;
}

function p95(ms: number[]): number {
  if (ms.length === 0) return 0;
  const s = [...ms].sort((a, b) => a - b);
  return s[Math.floor(0.95 * (s.length - 1))];
}

/** Evenly spaced indices in [0, n), up to `count` points. */
function sampleIndices(n: number, count: number): number[] {
  if (count >= n) return Array.from({ length: n }, (_, i) => i);
  const out: number[] = [];
  for (let j = 0; j < count; j++) {
    out.push(Math.floor((j / Math.max(1, count - 1)) * (n - 1)));
  }
  return [...new Set(out)].sort((a, b) => a - b);
}

function defaultSampleCount(n: number): number {
  if (n <= 300) return Math.min(n, 12);
  if (n <= 1500) return Math.min(n, 28);
  if (n <= 4000) return Math.min(n, 48);
  return Math.min(n, 64);
}

/** Default `recall.limit` so k = limit*3 scales with N (override LONGMEM_RECALL_LIMIT). */
function defaultRecallLimit(n: number): number {
  if (n <= 400) return 15;
  if (n <= 2000) return 35;
  if (n <= 6000) return 55;
  return 80;
}

/** Natural-language query that references fact `i` without copying the stored sentence. */
function paraphraseQuery(i: number): string {
  return `LongMem benchmark fact ${i}: what is the secret token for index ${i}?`;
}

describe('LongMem eval', () => {
  const agentId = 'longmem-bench-agent';
  const n = Math.max(10, parseEnvInt('LONGMEM_N', 200));
  const sampleCount = Math.min(n, parseEnvInt('LONGMEM_SAMPLES', defaultSampleCount(n)));
  const recallLimit = parseEnvInt('LONGMEM_RECALL_LIMIT', defaultRecallLimit(n));
  const useSemanticEmbeddings = process.env['LONGMEM_EMBEDDINGS'] === 'semantic';
  const vecKMult = parseEnvInt('LONGMEM_VEC_K_MULT', 3);
  let sdk: MnemoPay;

  beforeAll(() => {
    if (fs.existsSync(BENCH_DIR)) {
      try { fs.rmSync(BENCH_DIR, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    fs.mkdirSync(BENCH_DIR, { recursive: true });
    sdk = MnemoPay.create({
      agentId,
      persistDir: BENCH_DIR,
      vectorKMultiplier: vecKMult,
      ...(useSemanticEmbeddings
        ? { embeddings: 'semantic' as const, embeddingDimensions: 384 }
        : {}),
    });
  });

  afterAll(() => {
    if (sdk) sdk.close();
    try { fs.rmSync(BENCH_DIR, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('memory_vectors schema includes agent_id partition key', () => {
    const row = sdk.db.prepare(
      `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'memory_vectors'`,
    ).get() as { sql: string } | undefined;
    expect(row?.sql ?? '').toMatch(/agent_id\s+TEXT\s+PARTITION\s+KEY/i);
  });

  it('retain N memories; measure exact vs paraphrase recall', async () => {
    const tRetain: number[] = [];
    const contents: string[] = [];
    const rateLimiter = (sdk as any).rateLimiter;

    for (let i = 0; i < n; i++) {
      if (i > 0 && i % 200 === 0) rateLimiter.reset(agentId);
      const content = `LongMem benchmark fact ${i}: the secret token for index ${i} is MEM-${i}-TOKEN`;
      contents.push(content);
      const t0 = performance.now();
      await sdk.memory.retain(content, {
        source: 'observation',
        sessionId: 'longmem-session',
        tags: ['longmem', `i${i}`],
        importance: 0.5 + (i % 10) * 0.01,
      });
      tRetain.push(performance.now() - t0);
    }

    const idx = sampleIndices(n, sampleCount);

    // Exact query
    const tExact: number[] = [];
    let hits3 = 0;
    for (const i of idx) {
      const queryText = contents[i];
      const t0 = performance.now();
      const results = await sdk.memory.recall({
        text: queryText,
        limit: recallLimit,
        threshold: 0.0,
      });
      tExact.push(performance.now() - t0);
      if (results.slice(0, 3).some(r => r.memory.content === queryText)) hits3 += 1;
    }
    const exactHitRate = hits3 / idx.length;

    console.log('\n[LongMem eval — exact query]', JSON.stringify({
      mode: 'exact_query',
      memories: n,
      recallLimit,
      samples: idx.length,
      recallMsAvg: tExact.reduce((a, b) => a + b, 0) / tExact.length,
      hitAt3: exactHitRate,
    }, null, 2));

    // Paraphrase
    const tPara: number[] = [];
    let hit5 = 0;
    for (const i of idx) {
      const needle = `MEM-${i}-TOKEN`;
      const t0 = performance.now();
      const results = await sdk.memory.recall({
        text: paraphraseQuery(i),
        limit: recallLimit,
      });
      tPara.push(performance.now() - t0);
      const isHit = results.slice(0, 5).some(r => r.memory.content.includes(needle));
      if (isHit) {
        hit5 += 1;
      } else {
        console.log(`\n[LongMem MISS] index ${i}`);
        console.log(`  Query: "${paraphraseQuery(i)}"`);
        console.log(`  Expected needle: "${needle}"`);
        console.log(`  Top 5 results:`);
        results.slice(0, 5).forEach((r, j) => {
          console.log(`    ${j+1}. Score: ${r.score.toFixed(4)}, Content: "${r.memory.content.substring(0, 80)}..."`);
        });
      }
    }

    console.log('\n[LongMem eval — paraphrase]', JSON.stringify({
      mode: 'paraphrase_query',
      memories: n,
      samples: idx.length,
      recallMsAvg: tPara.reduce((a, b) => a + b, 0) / tPara.length,
      hitAt5: hit5 / idx.length,
    }, null, 2));

    expect(exactHitRate).toBeGreaterThanOrEqual(0.85);
  }, 1_800_000);

  describe('Decay Curve Comparison', () => {
    it('report hitAt5 for each decay curve', async () => {
      const curves: any[] = ['linear', 'exponential', 'logarithmic', 'none'];
      const results: Record<string, number> = {};

      for (const curve of curves) {
        const tempSdk = MnemoPay.create({
          agentId: `decay-${curve}`,
          persistDir: BENCH_DIR,
          decayCurve: curve,
          ...(useSemanticEmbeddings ? { embeddings: 'semantic', embeddingDimensions: 384 } : {}),
        });

        const content = "Decay test fact: the magic word is ABRA-CADABRA";
        await tempSdk.memory.retain(content, { source: 'observation', sessionId: 's', tags: [], importance: 0.5 });
        
        const recall = await tempSdk.memory.recall({ text: "What is the magic word?" });
        results[curve] = recall.some(r => r.memory.content.includes("ABRA-CADABRA")) ? 1 : 0;
        
        tempSdk.close();
      }
      console.log('\n[Decay Curve Comparison]', JSON.stringify(results, null, 2));
    });
  });

  describe('Candidate Pool Scaling', () => {
    it('measure hitAt5 and latency at 25/50/75 candidates', async () => {
      const pools = [25, 50, 75];
      const summary: any[] = [];

      for (const poolSize of pools) {
        const tempSdk = MnemoPay.create({
          agentId: `pool-${poolSize}`,
          persistDir: BENCH_DIR,
          candidateLimit: poolSize,
          ...(useSemanticEmbeddings ? { embeddings: 'semantic', embeddingDimensions: 384 } : {}),
        });

        // Add some noise memories
        for (let i = 0; i < 20; i++) {
          await tempSdk.memory.retain(`Noise memory ${i}`, { source: 'observation', sessionId: 's', tags: [], importance: 0.1 });
        }
        const target = "Target fact: the key is GOLDEN-KEY";
        await tempSdk.memory.retain(target, { source: 'observation', sessionId: 's', tags: [], importance: 0.8 });

        const start = performance.now();
        const recall = await tempSdk.memory.recall({ text: "What is the golden key?", limit: 5 });
        const latency = performance.now() - start;
        const hit = recall.some(r => r.memory.content.includes("GOLDEN-KEY")) ? 1 : 0;

        summary.push({ poolSize, hitAt5: hit, latencyMs: latency });
        tempSdk.close();
      }
      console.log('\n[Candidate Pool Scaling]', JSON.stringify(summary, null, 2));
    });
  });

  describe('Blend Ratio Comparison', () => {
    it('report hitAt5 for exact and paraphrase at various ratios', async () => {
      const ratios = [0.7, 0.8, 0.9];
      const results: any[] = [];

      const tempSdk = MnemoPay.create({
        agentId: 'blend-test',
        persistDir: BENCH_DIR,
        ...(useSemanticEmbeddings ? { embeddings: 'semantic', embeddingDimensions: 384 } : {}),
      });

      const fact = "The capital of France is Paris and its population is 2 million.";
      await tempSdk.memory.retain(fact, { source: 'observation', sessionId: 's', tags: [], importance: 0.5 });

      for (const ratio of ratios) {
        const exact = await tempSdk.memory.recall({ text: fact, blendRatio: ratio });
        const paraphrase = await tempSdk.memory.recall({ text: "Tell me about the population of the French capital", blendRatio: ratio });
        
        results.push({
          ratio,
          exactHit: exact.some(r => r.memory.content === fact) ? 1 : 0,
          paraHit: paraphrase.some(r => r.memory.content === fact) ? 1 : 0
        });
      }
      tempSdk.close();
      console.log('\n[Blend Ratio Comparison]', JSON.stringify(results, null, 2));
    });
  });

  describe('Query Classifier Accuracy', () => {
    it('test classification of sample queries', () => {
      const samples = [
        { q: "What happened yesterday?", expected: 'temporal' },
        { q: "Tell me about the meeting on 2024-05-12", expected: 'temporal' },
        { q: 'Who said "the bird is the word"?', expected: 'exact' },
        { q: "What did John Doe mention about Project X?", expected: 'exact' },
        { q: "What do you know about life?", expected: 'semantic' },
        { q: "How are you?", expected: 'semantic' },
      ];

      samples.forEach(s => {
        const res = classifyQuery(s.q);
        expect(res.type).toBe(s.expected);
      });
    });
  });
});
