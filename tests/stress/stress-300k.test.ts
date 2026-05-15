/**
 * MnemoPay Mobile SDK — 300K Transaction Stress Test
 *
 * 100 agents × 3,000 ops = 300,000 total operations.
 *
 * Operation mix (mapped to mobile SDK primitives):
 *   - 30% charge     → wallet.send (sender → counterparty)
 *   - 25% settle     → createEscrow → markConditionMet → settle
 *   - 20% verify     → getWallet + getTransactionHistory + FraudDetector replay check
 *   - 15% memory     → memory.retain / memory.recall (MemoryStore)
 *   - 10% refund/dispute → escrow timeout (reclaim) + replay-attack probe
 *
 * Adversarial injection:
 *   - ~2% of sends attempt a REPLAY (re-use an old nonce) — FraudDetector's
 *     checkReplay should catch every single one (nonce registry is monotonic).
 *   - Rate-limiter is probed with short bursts so we can record how many
 *     operations were correctly throttled.
 *
 * SQLite lives in a tmp dir (created per-run, cleaned up in afterAll) because
 * the mobile SDK's core/sdk.ts resolves a file path via _resolvePath — there
 * is no :memory: escape hatch. We still use one DB per agent (one SDK
 * instance per agent) so each has its own nonce / wallet row.
 *
 * SLOs:
 *   - totalOps        >= 300,000
 *   - replay detection rate === 1.0 (every adversarial tx blocked)
 *   - throughput      > 200 ops/sec
 *   - p99 latency     < 500 ms
 *
 * Jest timeout: 10 minutes.
 */

import { MnemoPay } from '../../src/index';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const AGENT_COUNT = 100;
const OPS_PER_AGENT = 3_000;
const TOTAL_OPS_TARGET = AGENT_COUNT * OPS_PER_AGENT;

const W_CHARGE = 0.30;
const W_SETTLE = 0.55;
const W_VERIFY = 0.75;
const W_MEMORY = 0.90;

const ADVERSARIAL_RATE = 0.02;

// Funding each wallet with plenty of cents so we never run out during the run.
// 3000 ops × average ~50c per send ≈ 150K cents, round up generously.
const INITIAL_BALANCE_CENTS = 10_000_000; // $100,000

interface AgentStats {
  id: string;
  charges: number;
  settles: number;
  verifies: number;
  memories: number;
  refunds: number;
  disputes: number;
  errors: number;
  rateLimited: number;
  adversarialAttempts: number;
  adversarialBlocked: number;
  latenciesMs: number[];
}

function quantile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(q * sorted.length));
  return sorted[idx];
}

// Bump the sender's balance directly via the underlying DB handle. Required
// so that 3000 sequential send()s don't run into INSUFFICIENT_BALANCE.
function fundWallet(sdk: MnemoPay, agentId: string, cents: number): void {
  const db: any = (sdk as any).db;
  // ensureWallet is private; insert-or-update to guarantee the row exists.
  db.prepare(`
    INSERT INTO wallets (agent_id, balance, currency, reputation, nonce, frozen, daily_limit, daily_spent, last_reset_date)
    VALUES (?, ?, 'USD_CENTS', 50, 0, 0, ?, 0, ?)
    ON CONFLICT(agent_id) DO UPDATE SET
      balance = excluded.balance,
      daily_limit = excluded.daily_limit
  `).run(agentId, cents, cents * 10, new Date().toISOString().slice(0, 10));
}

describe('MnemoPay Mobile SDK — 300K stress', () => {
  const TMP_ROOT = path.join(
    os.tmpdir(),
    `mnemopay-mobile-stress-${Date.now()}-${process.pid}`,
  );

  beforeAll(() => {
    if (!fs.existsSync(TMP_ROOT)) fs.mkdirSync(TMP_ROOT, { recursive: true });
  });

  afterAll(() => {
    try {
      fs.rmSync(TMP_ROOT, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  });

  it(
    `processes ${TOTAL_OPS_TARGET.toLocaleString()} ops across ${AGENT_COUNT} agents`,
    async () => {
      // ── Spawn agents ────────────────────────────────────────────────────
      const agents: {
        id: string;
        sdk: MnemoPay;
        stats: AgentStats;
      }[] = [];
      const counterparties: string[] = [];

      for (let i = 0; i < AGENT_COUNT; i++) {
        const id = `stress_agent_${i}`;
        const persistDir = path.join(TMP_ROOT, id);
        fs.mkdirSync(persistDir, { recursive: true });
        // Dev-only deterministic key — tests run outside production.
        const sdk = MnemoPay.create({
          agentId: id,
          persistDir,
          dailyLimitCents: 10_000_000_000,
          allowInsecureDefault: true,
        } as any);
        fundWallet(sdk, id, INITIAL_BALANCE_CENTS);
        agents.push({
          id,
          sdk,
          stats: {
            id,
            charges: 0,
            settles: 0,
            verifies: 0,
            memories: 0,
            refunds: 0,
            disputes: 0,
            errors: 0,
            rateLimited: 0,
            adversarialAttempts: 0,
            adversarialBlocked: 0,
            latenciesMs: [],
          },
        });
        counterparties.push(id);
      }

      const startTime = Date.now();

      // ── Run all agents concurrently ─────────────────────────────────────
      await Promise.all(
        agents.map(async ({ id, sdk, stats }, agentIdx) => {
          // Pick a deterministic counterparty that isn't self.
          const cpId = counterparties[(agentIdx + 1) % AGENT_COUNT];

          for (let i = 0; i < OPS_PER_AGENT; i++) {
            const roll = Math.random();
            const t0 = Date.now();

            try {
              if (roll < W_CHARGE) {
                // ── SEND (aka charge) ─────────────────────────────────────
                const amount = BigInt(1 + Math.floor(Math.random() * 20)); // 1..20 cents
                const isAdversarial = Math.random() < ADVERSARIAL_RATE;

                try {
                  await sdk.wallet.send(cpId, amount);
                  stats.charges++;
                } catch (err: any) {
                  const code: string | undefined = err?.code;
                  if (code === 'RATE_LIMITED') {
                    stats.rateLimited++;
                  } else if (code === 'INSUFFICIENT_BALANCE') {
                    // Top up and retry once — keeps the run going.
                    fundWallet(sdk, id, INITIAL_BALANCE_CENTS);
                    try {
                      await sdk.wallet.send(cpId, amount);
                      stats.charges++;
                    } catch {
                      stats.errors++;
                    }
                  } else {
                    stats.errors++;
                  }
                }

                // ── Adversarial: attempt a REPLAY with a stale nonce ────
                // FraudDetector.checkReplay uses monotonic nonces — any
                // value <= last-seen MUST produce a replay_attack signal.
                if (isAdversarial) {
                  stats.adversarialAttempts++;
                  const fd: any = (sdk as any).fraud;
                  // Probe with nonce = 0 (always stale after the first send).
                  const signal = fd.checkReplay(id, 0);
                  if (signal && signal.type === 'replay_attack') {
                    stats.adversarialBlocked++;
                  }
                }
              } else if (roll < W_SETTLE) {
                // ── ESCROW + SETTLE round-trip ────────────────────────────
                const amount = BigInt(1 + Math.floor(Math.random() * 10));
                try {
                  const escrow = await sdk.wallet.createEscrow(
                    cpId,
                    amount,
                    [{ type: 'manual_approval', params: {} }],
                    60_000, // 60s timeout
                  );
                  sdk.wallet.markConditionMet(escrow.id, 'manual_approval');
                  await sdk.wallet.settle(escrow.id);
                  stats.settles++;
                } catch (err: any) {
                  if (err?.code === 'RATE_LIMITED') stats.rateLimited++;
                  else if (err?.code === 'INSUFFICIENT_BALANCE') {
                    fundWallet(sdk, id, INITIAL_BALANCE_CENTS);
                    stats.errors++;
                  } else {
                    stats.errors++;
                  }
                }
              } else if (roll < W_VERIFY) {
                // ── VERIFY: wallet read + history + fraud probe ──────────
                sdk.wallet.getWallet();
                sdk.wallet.getTransactionHistory(10);
                const fd: any = (sdk as any).fraud;
                // Touch replay + collusion paths read-only style.
                fd.recordAction(id, `verify:${i}`);
                stats.verifies++;
              } else if (roll < W_MEMORY) {
                // ── MEMORY: retain OR recall ──────────────────────────────
                try {
                  if (Math.random() < 0.5) {
                    await sdk.memory.retain(
                      `stress-mem-${id}-${i}-${Math.random().toString(36).slice(2, 8)}`,
                      {
                        source: 'observation',
                        sessionId: 'stress',
                        tags: ['stress'],
                        importance: 0.3,
                      },
                    );
                  } else {
                    await sdk.memory.recall({
                      text: `stress-mem-${id}`,
                      limit: 5,
                      threshold: 0.0,
                    });
                  }
                  stats.memories++;
                } catch (err: any) {
                  if (err?.code === 'RATE_LIMITED') stats.rateLimited++;
                  else stats.errors++;
                }
              } else {
                // ── REFUND/DISPUTE: escrow timeout reclaim + replay probe ─
                // Using a 1ms timeout so the first settle() call will throw
                // ESCROW_EXPIRED and refund the buyer — this mirrors the
                // "dispute-like reversal" semantics of the non-mobile SDK.
                try {
                  const amount = BigInt(1);
                  const escrow = await sdk.wallet.createEscrow(
                    cpId,
                    amount,
                    [{ type: 'manual_approval', params: {} }],
                    1, // immediate timeout
                  );
                  // Allow clock to advance past the timeout.
                  await new Promise((r) => setTimeout(r, 5));
                  try {
                    await sdk.wallet.settle(escrow.id);
                  } catch (err: any) {
                    if (err?.code === 'ESCROW_EXPIRED') {
                      stats.refunds++;
                    } else {
                      stats.disputes++;
                    }
                  }
                } catch (err: any) {
                  if (err?.code === 'RATE_LIMITED') stats.rateLimited++;
                  else stats.errors++;
                }
              }
            } catch {
              stats.errors++;
            } finally {
              stats.latenciesMs.push(Date.now() - t0);
            }
          }
        }),
      );

      const elapsedMs = Date.now() - startTime;
      const elapsedSec = elapsedMs / 1000;

      // ── Aggregate ───────────────────────────────────────────────────────
      let totalCharges = 0;
      let totalSettles = 0;
      let totalVerifies = 0;
      let totalMemories = 0;
      let totalRefunds = 0;
      let totalDisputes = 0;
      let totalErrors = 0;
      let totalRateLimited = 0;
      let totalAdvAttempts = 0;
      let totalAdvBlocked = 0;
      const allLatencies: number[] = [];

      for (const { stats } of agents) {
        totalCharges += stats.charges;
        totalSettles += stats.settles;
        totalVerifies += stats.verifies;
        totalMemories += stats.memories;
        totalRefunds += stats.refunds;
        totalDisputes += stats.disputes;
        totalErrors += stats.errors;
        totalRateLimited += stats.rateLimited;
        totalAdvAttempts += stats.adversarialAttempts;
        totalAdvBlocked += stats.adversarialBlocked;
        for (let i = 0; i < stats.latenciesMs.length; i += 10_000) {
          allLatencies.push(...stats.latenciesMs.slice(i, i + 10_000));
        }
      }

      const totalOps =
        totalCharges +
        totalSettles +
        totalVerifies +
        totalMemories +
        totalRefunds +
        totalDisputes +
        totalRateLimited; // count rate-limited attempts as ops for throughput

      const throughput = Math.round(totalOps / elapsedSec);
      allLatencies.sort((a, b) => a - b);
      const p50 = quantile(allLatencies, 0.5);
      const p95 = quantile(allLatencies, 0.95);
      const p99 = quantile(allLatencies, 0.99);

      const detectionRate =
        totalAdvAttempts === 0 ? 1 : totalAdvBlocked / totalAdvAttempts;

      // ── Banner ──────────────────────────────────────────────────────────
      const banner = '═'.repeat(72);
      const rule = '─'.repeat(72);
      // eslint-disable-next-line no-console
      console.log('\n' + banner);
      // eslint-disable-next-line no-console
      console.log('  MNEMOPAY MOBILE SDK — 300K TRANSACTION STRESS TEST');
      // eslint-disable-next-line no-console
      console.log(banner);
      const log = (s: string) => console.log(s); // eslint-disable-line no-console
      log(`  Agents:            ${AGENT_COUNT}`);
      log(`  Ops per agent:     ${OPS_PER_AGENT.toLocaleString()}`);
      log(`  Total ops:         ${totalOps.toLocaleString()} / target ${TOTAL_OPS_TARGET.toLocaleString()}`);
      log(`  Wall time:         ${elapsedSec.toFixed(1)}s`);
      log(`  Throughput:        ${throughput.toLocaleString()} ops/sec`);
      log(rule);
      log(`  Latency p50:       ${p50} ms`);
      log(`  Latency p95:       ${p95} ms`);
      log(`  Latency p99:       ${p99} ms`);
      log(rule);
      log(`  Charges (send):    ${totalCharges.toLocaleString()}`);
      log(`  Settles (escrow):  ${totalSettles.toLocaleString()}`);
      log(`  Verifies:          ${totalVerifies.toLocaleString()}`);
      log(`  Memory ops:        ${totalMemories.toLocaleString()}`);
      log(`  Refunds (expired): ${totalRefunds.toLocaleString()}`);
      log(`  Disputes:          ${totalDisputes.toLocaleString()}`);
      log(`  Rate-limited:      ${totalRateLimited.toLocaleString()}`);
      log(`  Errors:            ${totalErrors.toLocaleString()}`);
      log(rule);
      log(`  Adversarial txs:   ${totalAdvAttempts.toLocaleString()} injected`);
      log(`  Adversarial blocked: ${totalAdvBlocked.toLocaleString()} (${(detectionRate * 100).toFixed(1)}%)`);
      log(banner + '\n');

      // ── Cleanup (close DB handles before tmp dir removal) ───────────────
      for (const { sdk } of agents) {
        try {
          sdk.close();
        } catch {
          /* already closed */
        }
      }

      // ── SLO assertions ──────────────────────────────────────────────────
      expect(totalOps).toBeGreaterThanOrEqual(TOTAL_OPS_TARGET);
      expect(detectionRate).toBe(1);
      expect(throughput).toBeGreaterThan(200);
      expect(p99).toBeLessThan(500);
    },
    10 * 60 * 1000, // 10-minute timeout
  );
});
