# @mnemopay/mobile-sdk

On-device persistent memory, agent-to-agent payments, and cryptographic spatial proofs for mobile AI apps.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [MemoryStore](#memorystore)
  - [WalletEngine](#walletengine)
  - [SpatialProver](#spatialprover)
- [API Reference](#api-reference)
- [Platform Support](#platform-support)

## Installation

Install the SDK using npm or yarn:

```bash
npm install @mnemopay/mobile-sdk
# or
yarn add @mnemopay/mobile-sdk
```

## Quick Start

### Basic Setup

To get started, you need to create an instance of the `MnemoPay` SDK. This requires an `agentId` and optionally a `persistDir` for the SQLite database.

```typescript
import { MnemoPay } from '@mnemopay/mobile-sdk';
import * as path from 'path';

// For Node.js, specify a persistence directory.
// For mobile platforms, the bridge will handle persistence.
const persistDir = path.join(process.cwd(), '.mnemopay_data');

const sdk = MnemoPay.create({
  agentId: 'your-unique-agent-id',
  persistDir: persistDir, // Omit for mobile builds
});

// Don't forget to close the SDK when your application exits
process.on('exit', () => sdk.close());
process.on('SIGINT', () => {
  sdk.close();
  process.exit();
});
```

### MemoryStore

The `MemoryStore` allows agents to retain, recall, and manage memories.

```typescript
import { MnemoPay } from '@mnemopay/mobile-sdk';
// ... (SDK initialization)

async function useMemoryStore() {
  // Retain a memory
  const memory = await sdk.memory.retain(
    'The user likes Italian food, especially pasta.',
    {
      source: 'conversation',
      sessionId: 'user-session-123',
      tags: ['preference', 'food'],
      importance: 0.7,
    }
  );
  console.log('Retained memory:', memory.id);

  // Recall memories related to a query
  const results = await sdk.memory.recall({
    text: 'What kind of food does the user prefer?',
    threshold: 0.5, // cosine similarity threshold
    limit: 5,
  });

  if (results.length > 0) {
    console.log('Recalled memories:');
    results.forEach(r => console.log(`- Score: ${r.score.toFixed(2)}, Content: ${r.memory.content}`));
  } else {
    console.log('No relevant memories found.');
  }

  // Auto-retain salient facts from a conversation
  await sdk.memory.autoRetain(
    'User said: "I really enjoy cooking with fresh herbs." Agent said: "That's great!"',
    'user-session-123'
  );

  // Forget a memory
  // await sdk.memory.forget(memory.id);
}

useMemoryStore();
```

### WalletEngine

The `WalletEngine` enables agent-to-agent payments, escrow contracts, and transaction history. Payments are in USD cents (BigInt).

```typescript
import { MnemoPay } from '@mnemopay/mobile-sdk';
// ... (SDK initialization)

async function useWalletEngine() {
  const myAgentId = sdk.wallet.getWallet().agentId;
  const otherAgentId = 'another-agent-id';

  // Get current wallet balance
  const myWallet = sdk.wallet.getWallet();
  console.log(`My balance: ${myWallet.balance} USD cents`);

  // Fund wallet for testing (in a real app, this would come from a trusted source)
  // This is a direct DB update for demonstration purposes.
  (sdk as any).db.prepare('UPDATE wallets SET balance = ? WHERE agent_id = ?')
    .run(1000000, myAgentId); // 10000 USD cents = $100

  // Send a payment
  const amountToSend = 500n; // 5 USD cents
  try {
    const tx = await sdk.wallet.send(otherAgentId, amountToSend);
    console.log(`Payment sent! Transaction ID: ${tx.id}, Status: ${tx.status}`);
  } catch (error: any) {
    console.error('Payment failed:', error.message);
  }

  // Create an escrow contract
  const escrowAmount = 1000n; // 10 USD cents
  try {
    const escrow = await sdk.wallet.createEscrow(
      otherAgentId,
      escrowAmount,
      [{ type: 'spatial_proof', params: { h3Tile: '8928308280bffff' } }] // Condition: spatial proof at a specific H3 tile
    );
    console.log(`Escrow created! ID: ${escrow.id}, Status: ${escrow.status}`);

    // Simulate condition met (e.g., SpatialProver verifies location)
    sdk.wallet.markConditionMet(escrow.id, 'spatial_proof');

    // Settle the escrow
    const settleTx = await sdk.wallet.settle(escrow.id);
    console.log(`Escrow settled! Transaction ID: ${settleTx.id}, Status: ${settleTx.status}`);

  } catch (error: any) {
    console.error('Escrow operation failed:', error.message);
  }

  // Get transaction history
  const history = sdk.wallet.getTransactionHistory();
  console.log('Transaction History:', history);
}

useWalletEngine();
```

### SpatialProver

The `SpatialProver` generates and verifies cryptographic proofs of an agent's location, based on GPS and sensor readings.

```typescript
import { MnemoPay } from '@mnemopay/mobile-sdk';
// ... (SDK initialization)

async function useSpatialProver() {
  const deviceId = 'mobile-device-xyz'; // Unique device identifier

  // Generate a spatial proof
  const lat = 34.0522; // Example Latitude
  const lng = -118.2437; // Example Longitude
  const accuracy = 5; // GPS accuracy in meters (e.g., 5m)
  const confidence = 0.95; // Scene recognition confidence (0-1)
  const sensorReadings = {
    wifi_bssid: ['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'],
    bluetooth_beacons: [{ id: 'beacon-1', rssi: -70 }],
  };

  try {
    const proofResult = await sdk.spatial.prove(
      lat, lng, accuracy, confidence, sensorReadings, deviceId
    );
    console.log('Spatial Proof Generated:', proofResult.proof.id);
    console.log('Proof Passed:', proofResult.passed, 'Score:', proofResult.score);

    // Verify a spatial proof (e.g., from another agent or a previous proof)
    const verificationResult = await sdk.spatial.verify(proofResult.proof.id);
    console.log('Spatial Proof Verified:', verificationResult.passed);
    console.log('Verification Score:', verificationResult.score);

  } catch (error: any) {
    console.error('Spatial Proof failed:', error.message);
  }
}

useSpatialProver();
```

## API Reference

The core SDK object is `MnemoPay`. It exposes the following main modules:

*   **`sdk.memory: MemoryStore`**: Manages memory retention, recall, and auto-processing.
    *   `retain(content: string, metadata: MemoryMetadata): Promise<Memory>`
    *   `recall(query: MemoryQuery): Promise<MemoryRecallResult[]>`
    *   `autoRetain(conversation: string, sessionId: string): Promise<Memory[]>`
    *   `autoRecall(userMessage: string, tokenBudget?: number): Promise<string>`
    *   `forget(memoryId: string): Promise<void>`
    *   `count(): number`
*   **`sdk.wallet: WalletEngine`**: Handles agent wallets, transactions, and escrow.
    *   `getWallet(agentId?: string): AgentWallet`
    *   `send(toAgent: string, amount: bigint, memoriesAccessed?: string[]): Promise<Transaction>`
    *   `createEscrow(sellerAgent: string, amount: bigint, conditions: Omit<EscrowCondition, 'met'>[], timeoutMs?: number): Promise<EscrowContract>`
    *   `settle(escrowId: string, memoriesAccessed?: string[]): Promise<Transaction>`
    *   `markConditionMet(escrowId: string, conditionType: EscrowCondition['type']): void`
    *   `freezeWallet(agentId: string): void`
    *   `getTransactionHistory(limit?: number): Transaction[]`
*   **`sdk.spatial: SpatialProver`**: Provides spatial proof generation and verification.
    *   `prove(lat: number, lng: number, accuracy: number, confidence: number, sensorReadings: Record<string, unknown>, deviceId: string, attestationToken?: string, isRooted?: boolean): Promise<SpatialProofResult>`
    *   `verify(proofId: string, expectedH3Tile?: string): Promise<SpatialProofResult>`
    *   `proveAndMarkEscrow(escrowId: string, conditionType: 'spatial_proof', markConditionFn: (escrowId: string, type: 'spatial_proof') => void, lat: number, lng: number, accuracy: number, confidence: number, sensorReadings: Record<string, unknown>, deviceId: string, expectedH3Tile?: string): Promise<SpatialProofResult>`
    *   `getProof(proofId: string): SpatialProof | null`
    *   `getProofHistory(limit?: number): SpatialProof[]`
*   **`sdk.sync: EncryptedSync`**: Manages encrypted, zero-knowledge cloud synchronization.
    *   `buildPushPacket(tables?: string[]): Promise<SyncPacket>`
    *   `applyPullPacket(packet: SyncPacket): Promise<{ merged: number; skipped: number }>`
    *   `markSynced(recordIds: string[]): void`
    *   `getSyncStatus(): { pendingPush: number; lastSync: number | null }`

For detailed type definitions, refer to `src/types/index.ts`.

## Platform Support

The SDK is designed for cross-platform compatibility with specific bridges for different environments.

*   **Node.js**: Full support, primarily for server-side or desktop agent applications. Uses `NodeBridge` by default.
*   **Android/iOS**: Mobile bridges (`AndroidBridge`, `IOSBridge`) are available in `platform/index.ts`. These bridges integrate with platform-specific APIs for cryptography, storage, and attestation. To use a mobile bridge, call `MnemoPay.setPlatformBridge()` before `MnemoPay.create()`:

    ```typescript
    import { MnemoPay, AndroidBridge } from '@mnemopay/mobile-sdk';

    // For Android:
    MnemoPay.setPlatformBridge(new AndroidBridge());
    const sdk = MnemoPay.create({ agentId: 'your-android-agent' });

    // For iOS (similar approach):
    // import { MnemoPay, IOSBridge } from '@mnemopay/mobile-sdk';
    // MnemoPay.setPlatformBridge(new IOSBridge());
    // const sdk = MnemoPay.create({ agentId: 'your-ios-agent' });
    ```

    Mobile environments might require specific build steps or permissions for SQLite and native cryptography modules. Please refer to the respective platform documentation for details.

### RL Feedback — Reinforcement Learning for Memory

After a recall + agent action, you can signal whether the recalled memories were useful. This updates each memory's `importance` score via EWMA so future recalls surface better results.

```typescript
// Recall memories for a query
const results = await sdk.memory.recall({ text: 'user dietary preferences', limit: 5 });

// ... agent acts on the recalled memories ...

// Signal reward: +1 = very useful, 0 = neutral, -1 = useless
sdk.memory.reinforceBatch(results.map(r => r.memory.id), 1.0);

// Or reinforce a single memory
sdk.memory.reinforce(results[0].memory.id, 0.8, /* alpha= */ 0.1);
```

EWMA update: `new_importance = α × ((reward+1)/2) + (1−α) × old_importance`

---
**License**: Apache-2.0
**Author**: Jerry Omiagbo
