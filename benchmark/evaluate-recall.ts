#!/usr/bin/env node
/**
 * LongMemEval runner for @mnemopay/mobile-sdk
 * Uses the same oracle dataset as the main SDK benchmark.
 *
 * Usage:
 *   npx tsx benchmark/evaluate-recall.ts --max 500
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { MnemoPay } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface Turn { role: string; content: string; }
interface LongMemEvalInstance {
  question_id: string;
  question_type: string;
  question: string;
  answer: string | number;
  haystack_sessions: Turn[][];
  haystack_session_ids: string[];
  haystack_dates: string[];
  answer_session_ids?: string[];
}

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (flag: string, fallback: string) => {
    const idx = args.indexOf(flag);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
  };
  return {
    dataFile: get('--data', join(__dirname, '../../mnemopay-sdk/benchmark/longmemeval/data/longmemeval_oracle.json')),
    recallLimit: parseInt(get('--recall-limit', '20'), 10),
    maxQuestions: parseInt(get('--max', '0'), 10),
    // vectorKMultiplier: cast wider net during eval for paraphrased queries.
    // Default 12 mirrors the main SDK LONGMEM_VEC_K_MULT=12 tuning.
    vectorKMultiplier: parseInt(process.env.LONGMEM_VEC_K_MULT ?? get('--vec-k-mult', '12'), 10),
  };
}

function formatSession(turns: Turn[], sessionId: string, date: string): string {
  const lines = [`[Session ${sessionId} — ${date}]`];
  for (const turn of turns) {
    lines.push(`${turn.role === 'human' ? 'User' : 'Assistant'}: ${turn.content}`);
  }
  return lines.join('\n');
}

function chunkContent(content: string, maxChars: number): string[] {
  if (content.length <= maxChars) return [content];
  const lines = content.split('\n');
  const chunks: string[] = [];
  let current = '';
  for (const line of lines) {
    if (current.length + line.length + 1 > maxChars && current.length > 0) {
      chunks.push(current);
      current = line;
    } else {
      current += (current ? '\n' : '') + line;
    }
  }
  if (current) chunks.push(current);
  return chunks;
}

function containsAnswer(text: string, answer: string | number): boolean {
  const t = text.toLowerCase();
  const a = String(answer).toLowerCase().trim();
  if (t.includes(a)) return true;
  const words = a.split(/\s+/).filter(w => w.length > 3);
  if (words.length >= 2) return words.filter(w => t.includes(w)).length / words.length >= 0.7;
  if (words.length === 1) return t.includes(words[0]);
  return false;
}

async function main() {
  const opts = parseArgs();

  console.log('\n=== MnemoPay Mobile SDK — LongMemEval ===');
  console.log(`Data: ${opts.dataFile}`);
  console.log(`Recall limit: ${opts.recallLimit}`);
  console.log(`Vector K multiplier: ${opts.vectorKMultiplier}`);

  const raw = readFileSync(opts.dataFile, 'utf-8');
  const dataset: LongMemEvalInstance[] = JSON.parse(raw);
  const instances = opts.maxQuestions > 0 ? dataset.slice(0, opts.maxQuestions) : dataset;

  console.log(`\nProcessing ${instances.length} questions...\n`);

  const t0 = Date.now();
  let answerHits = 0;
  let sessionHits = 0;
  const byType: Record<string, { answerHit: number; sessionHit: number; total: number }> = {};
  const details: any[] = [];

  for (const inst of instances) {
    const persistDir = join(os.tmpdir(), `mobile-lme-${inst.question_id}-${randomUUID()}`);
    mkdirSync(persistDir, { recursive: true });

    const sdk = MnemoPay.create({
      agentId: `lme-${inst.question_id}`,
      persistDir,
      vectorKMultiplier: opts.vectorKMultiplier,
      embeddings: 'semantic',   // use all-MiniLM-L6-v2 — hash vectors have zero semantic signal
    });

    // Ingest all sessions
    for (let i = 0; i < inst.haystack_sessions.length; i++) {
      const sessionId = inst.haystack_session_ids[i] ?? `session-${i}`;
      const date = inst.haystack_dates[i] ?? 'unknown';
      const content = formatSession(inst.haystack_sessions[i], sessionId, date);
      for (const chunk of chunkContent(content, 8000)) {
        await sdk.memory.retain(chunk, {
          source: 'observation',
          sessionId,
          tags: [`session:${sessionId}`, `date:${date}`],
          importance: 0.7,
        });
      }
    }

    // Recall
    const recalled = await sdk.memory.recall({ text: inst.question, limit: opts.recallLimit, threshold: 0.0 });
    const recalledTexts = recalled.map(r => r.memory.content);
    const joined = recalledTexts.join('\n');

    const answerFound = containsAnswer(joined, inst.answer);
    const answerSessionIds = new Set(inst.answer_session_ids ?? []);
    const recalledSessionIds = recalledTexts
      .map(t => { const m = t.match(/\[Session (\S+)/); return m ? m[1] : null; })
      .filter(Boolean) as string[];
    const sessionFound = recalledSessionIds.some(sid => answerSessionIds.has(sid));

    const qtype = inst.question_type ?? 'unknown';
    if (!byType[qtype]) byType[qtype] = { answerHit: 0, sessionHit: 0, total: 0 };
    byType[qtype].total++;
    if (answerFound) { answerHits++; byType[qtype].answerHit++; }
    if (sessionFound) { sessionHits++; byType[qtype].sessionHit++; }

    details.push({
      qid: inst.question_id,
      qtype,
      question: inst.question,
      answer: String(inst.answer),
      answerFound,
      sessionFound,
      recallCount: recalled.length,
    });

    sdk.close();
  }

  const timeMs = Date.now() - t0;
  const total = instances.length;

  const summary = {
    totalQuestions: total,
    answerInRecalled: { count: answerHits, pct: ((answerHits / total) * 100).toFixed(1) },
    sessionHitRate: { count: sessionHits, pct: ((sessionHits / total) * 100).toFixed(1) },
    byType: Object.fromEntries(
      Object.entries(byType).map(([k, v]) => [k, {
        total: v.total,
        answerHit: v.answerHit,
        answerHitPct: ((v.answerHit / v.total) * 100).toFixed(1),
        sessionHit: v.sessionHit,
        sessionHitPct: ((v.sessionHit / v.total) * 100).toFixed(1),
      }])
    ),
    timeMs,
  };

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const outDir = join(__dirname, 'results', `mobile_recall_${timestamp}`);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));
  writeFileSync(join(outDir, 'details.json'), JSON.stringify(details, null, 2));

  console.log('\n=== RESULTS ===');
  console.log(`Answer hit rate: ${summary.answerInRecalled.pct}% (${answerHits}/${total})`);
  console.log(`Session hit rate: ${summary.sessionHitRate.pct}%`);
  console.log('\nBy type:');
  for (const [type, stats] of Object.entries(summary.byType)) {
    console.log(`  ${type}: ${(stats as any).answerHitPct}% answer hit`);
  }
  console.log(`\nTime: ${(timeMs / 1000).toFixed(1)}s`);
  console.log(`Results saved to: ${outDir}`);
}

main().catch(console.error);
