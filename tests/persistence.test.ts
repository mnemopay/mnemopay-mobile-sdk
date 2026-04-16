import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { FraudDetector } from '../src/security/fraud-detector';
import { RateLimiter } from '../src/security/rate-limiter';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEST_DB_DIR = path.join(__dirname, 'tmp-persistence');

describe('Security persistence', () => {
  let dbPath: string;

  beforeAll(() => {
    if (fs.existsSync(TEST_DB_DIR)) {
      try { fs.rmSync(TEST_DB_DIR, { recursive: true, force: true }); } catch {}
    }
    fs.mkdirSync(TEST_DB_DIR, { recursive: true });
    dbPath = path.join(TEST_DB_DIR, 'security.db');
  });

  afterAll(() => {
    try { fs.rmSync(TEST_DB_DIR, { recursive: true, force: true }); } catch {}
  });

  describe('FraudDetector', () => {
    it('replay protection survives restart', () => {
      const db1 = new Database(dbPath);
      FraudDetector.initSchema(db1);
      const fd1 = new FraudDetector(db1);
      expect(fd1.checkReplay('agent-x', 10)).toBeNull();
      expect(fd1.checkReplay('agent-x', 20)).toBeNull();
      db1.close();

      const db2 = new Database(dbPath);
      const fd2 = new FraudDetector(db2);
      // Replaying nonce 20 must be rejected after restart.
      const replay = fd2.checkReplay('agent-x', 20);
      expect(replay?.type).toBe('replay_attack');
      // Nonce 15 is also below the last-seen 20 and must be rejected.
      const old = fd2.checkReplay('agent-x', 15);
      expect(old?.type).toBe('replay_attack');
      // Advancing beyond 20 is still allowed.
      expect(fd2.checkReplay('agent-x', 21)).toBeNull();
      db2.close();
    });

    it('collusion graph survives restart', () => {
      const dbPath2 = path.join(TEST_DB_DIR, 'collusion.db');
      const db1 = new Database(dbPath2);
      FraudDetector.initSchema(db1);
      const fd1 = new FraudDetector(db1);
      // Build up to the collusion threshold minus one in each direction.
      fd1.checkCollusion('A', 'B');
      fd1.checkCollusion('A', 'B');
      fd1.checkCollusion('B', 'A');
      fd1.checkCollusion('B', 'A');
      db1.close();

      const db2 = new Database(dbPath2);
      const fd2 = new FraudDetector(db2);
      // Third hit in each direction should trip the detector.
      fd2.checkCollusion('A', 'B');
      const signal = fd2.checkCollusion('B', 'A');
      expect(signal?.type).toBe('collusion_pattern');
      db2.close();
    });
  });

  describe('RateLimiter', () => {
    it('per-agent timestamps survive restart', () => {
      const dbPath3 = path.join(TEST_DB_DIR, 'rate.db');
      const db1 = new Database(dbPath3);
      RateLimiter.initSchema(db1);
      const rl1 = new RateLimiter(db1);
      // 'transaction' category allows 50/hour. Fire 50 to fill the window.
      for (let i = 0; i < 50; i++) {
        const { allowed } = rl1.check('agent-y', 'transaction');
        expect(allowed).toBe(true);
      }
      db1.close();

      const db2 = new Database(dbPath3);
      const rl2 = new RateLimiter(db2);
      // After restart, the same agent should start eating burst tokens; 10 burst
      // tokens max, so call 11 is the first to be denied.
      let firstDeniedIndex = -1;
      for (let i = 0; i < 11; i++) {
        const { allowed } = rl2.check('agent-y', 'transaction');
        if (!allowed && firstDeniedIndex === -1) firstDeniedIndex = i;
      }
      expect(firstDeniedIndex).toBe(10);
      db2.close();
    });
  });
});
