# UPI Offline Mesh

> **Deferred settlement UPI payments routed through a Bluetooth-style gossip mesh — no internet required at the point of transaction.**

A Spring Boot backend that simulates and processes offline UPI payments propagated through a device mesh. A payment encrypted on the sender's phone hops across offline intermediary devices via Bluetooth gossip until a bridge node regains connectivity and uploads it to the backend — which then decrypts, deduplicates, and settles it atomically.

This repository is the **server-side engine** plus a full in-process mesh simulator so the entire flow can be demonstrated on a single machine without any Bluetooth hardware.

---

## Table of Contents

1. [Why This Project Exists](#why-this-project-exists)
2. [What Makes This Technically Interesting](#what-makes-this-technically-interesting)
3. [Key Features](#key-features)
4. [System Architecture](#system-architecture)
5. [End-to-End Flow](#end-to-end-flow)
6. [The Three Hard Problems](#the-three-hard-problems)
7. [Cryptography Deep Dive](#cryptography-deep-dive)
8. [Idempotency Design](#idempotency-design)
9. [Settlement Pipeline](#settlement-pipeline)
10. [Security Considerations](#security-considerations)
11. [Dashboard Walkthrough](#dashboard-walkthrough)
12. [API Reference](#api-reference)
13. [Folder Structure](#folder-structure)
14. [Running Locally](#running-locally)
15. [Running Tests](#running-tests)
16. [Production-Grade Improvements](#production-grade-improvements)
17. [Real-World Constraints and Limitations](#real-world-constraints-and-limitations)
18. [Future Enhancements](#future-enhancements)
19. [License](#license)

---

## Why This Project Exists

India has ~500 million UPI users. A significant portion operate in environments with patchy connectivity — metro basements, rural areas, crowded stadiums, disaster zones. The current UPI stack is 100% online: every transaction requires a live NPCI round-trip. This project explores a credible alternative architecture: what if you could sign a payment offline, propagate it peer-to-peer through whoever is nearby, and have it settle the moment *anyone* in the chain gets internet?

The core claim this project validates: **you can build a cryptographically secure, replay-resistant, exactly-once settlement system on top of an unreliable, untrusted gossip mesh** — using nothing fancier than hybrid RSA+AES encryption and an atomic compare-and-set operation.

---

## What Makes This Technically Interesting

**1. The trust model is inverted from conventional payment systems.**
Normally you trust the transport (TLS) and conditionally trust the endpoint. Here the transport is actively adversarial — any hop could inspect, copy, or attempt to replay the packet. The system still achieves integrity and confidentiality because the cryptographic protection lives inside the payload, not in the channel.

**2. Idempotency is the key primitive, not consensus.**
Most distributed systems that need exactly-once semantics reach for distributed consensus (Paxos, Raft). This system instead makes each packet a content-addressed blob (SHA-256 of the ciphertext) and uses an atomic claim operation as the gate. Simpler, faster, and sufficient for this domain.

**3. Authenticated encryption eliminates a whole class of attacks.**
AES-GCM is not just encryption — it's encryption *plus* authentication. The 16-byte GCM tag over the ciphertext means any single-bit mutation in transit is detected on decryption. Intermediaries cannot selectively corrupt fields and have it go unnoticed.

**4. The dedup key is the ciphertext hash, not the application-layer ID.**
`packetId` lives in the outer cleartext envelope and can be rewritten by any intermediate. The ciphertext is immutable (any change invalidates the GCM tag). Deduplication on `SHA-256(ciphertext)` is therefore tamper-proof. This is a subtle but critical design choice.

**5. Defense in depth across three independent layers.**
Idempotency cache (application layer) → unique DB index on `packet_hash` (database layer) → `@Version` optimistic locking on `Account` (ORM layer). Each layer is independently sufficient; together they make double-settlement essentially impossible.

---

## Key Features

- **Hybrid RSA-OAEP + AES-256-GCM encryption** — payload is confidential and authenticated end-to-end
- **Gossip-based mesh propagation** with TTL-based flood control
- **Atomic idempotency** via `ConcurrentHashMap.putIfAbsent` (JVM-local `SETNX` semantics)
- **Replay attack prevention** via nonce + `signedAt` freshness window
- **Tamper detection** — any mutation of the ciphertext causes immediate rejection
- **Optimistic locking** on account balances via `@Version` (JPA)
- **Transactional settlement** — debit and credit are atomic at the DB level
- **Full mesh simulator** — virtual devices, gossip rounds, bridge uploads, all driven via REST
- **Interactive dashboard** — dark-themed, real-time, no external JS framework
- **H2 in-memory DB** — zero-dependency setup, runs with just JDK 17

---

## System Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          SENDER PHONE  (offline)                            ║
║                                                                              ║
║   PaymentInstruction {                                                       ║
║     senderVpa, receiverVpa, amount,                                          ║
║     pinHash,   nonce (UUID),  signedAt (epoch ms)                            ║
║   }                                                                          ║
║          │                                                                   ║
║          ▼  encrypt(serverPublicKey) → HybridCryptoService                  ║
║                                                                              ║
║   MeshPacket {                                                               ║
║     packetId (UUID, outer, mutable)                                          ║
║     ttl      (decrements per hop)                                            ║
║     createdAt                                                                ║
║     ciphertext  ← [256B RSA-encrypted AES key][12B IV][AES-GCM payload+tag] ║
║   }                                                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
                │
                │  Bluetooth / BLE GATT (real)
                │  or in-process gossip simulation (demo)
                │
                ▼
  ┌─────────┐  hop  ┌──────────┐  hop  ┌──────────┐  hop  ┌──────────────┐
  │ phone-A │──────▶│stranger-1│──────▶│stranger-2│──────▶│ phone-bridge │
  │(sender) │       │(offline) │       │(offline) │       │(4G bridge)   │
  └─────────┘       └──────────┘       └──────────┘       └──────┬───────┘
                                                                  │
                                                         gets internet
                                                                  │ HTTPS POST
                                                                  ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SPRING BOOT BACKEND  (this project)                       ║
║                                                                              ║
║  POST /api/bridge/ingest                                                     ║
║       │                                                                      ║
║       ├─[1]─ SHA-256(ciphertext) → packetHash                                ║
║       │                                                                      ║
║       ├─[2]─ IdempotencyService.claim(packetHash)                            ║
║       │        ConcurrentHashMap.putIfAbsent  ≡  Redis SETNX                 ║
║       │        duplicate? → DUPLICATE_DROPPED (short-circuit)                ║
║       │                                                                      ║
║       ├─[3]─ HybridCryptoService.decrypt(ciphertext)                         ║
║       │        RSA-OAEP unwraps AES key                                      ║
║       │        AES-GCM decrypts + verifies auth tag                          ║
║       │        tampered? → AEADBadTagException → INVALID                     ║
║       │                                                                      ║
║       ├─[4]─ Freshness check: signedAt within ±24h                           ║
║       │        too old → stale_packet                                        ║
║       │        future-dated → future_dated                                   ║
║       │                                                                      ║
║       └─[5]─ SettlementService.settle()  (@Transactional)                   ║
║                debit sender   → accounts.save(sender)                       ║
║                credit receiver→ accounts.save(receiver)                     ║
║                write ledger   → transactions.save(tx)                       ║
║                @Version on Account → optimistic lock (defense-in-depth)     ║
║                unique idx on packetHash → DB-level dedup (defense-in-depth) ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## End-to-End Flow

### Phase 1 — Packet Construction (sender's phone)

```
User enters: sender VPA, receiver VPA, ₹amount, PIN
         │
         ▼
DemoService.createPacket()
  ├── Build PaymentInstruction
  │     senderVpa  = "ShubhamTiwari@demo"
  │     receiverVpa= "Sarvesh@demo"
  │     amount     = 500.00
  │     pinHash    = SHA-256("1234")
  │     nonce      = UUID.randomUUID()      ← unique per payment intent
  │     signedAt   = Instant.now().toEpochMilli()
  │
  ├── HybridCryptoService.encrypt(instruction, serverPublicKey)
  │     gen AES-256 key (fresh per packet)
  │     AES-GCM encrypt JSON → aesCiphertext
  │     RSA-OAEP encrypt AES key → encryptedAesKey
  │     pack: [encryptedAesKey][iv][aesCiphertext]
  │     base64-encode → ciphertext string
  │
  └── Wrap in MeshPacket
        packetId  = UUID.randomUUID()
        ttl       = 5
        createdAt = now
        ciphertext= (above)
```

### Phase 2 — Mesh Propagation (gossip)

```
Round 1:
  phone-alice (holds packet, TTL=5)
    → broadcasts to stranger-1 (TTL=4), stranger-2 (TTL=4), phone-bridge (TTL=4)

Round 2:
  all devices hold the packet, TTL decrements further
  devices that already hold a packetId skip it (dedup by packetId at hop layer)
  packets at TTL=0 are held but not forwarded
```

### Phase 3 — Bridge Upload

```
phone-bridge (hasInternet=true)
  for each held packet:
    POST /api/bridge/ingest
      headers: X-Bridge-Node-Id: phone-bridge
               X-Hop-Count: 3
      body: MeshPacket JSON
```

### Phase 4 — Server Ingestion Pipeline

```
receive packet
  │
  ├── hash = SHA-256(packet.ciphertext)
  │
  ├── idempotency.claim(hash)
  │     putIfAbsent(hash, Instant.now())
  │     if (prev != null) → return DUPLICATE_DROPPED
  │
  ├── instruction = crypto.decrypt(packet.ciphertext)
  │     RSA-OAEP → aesKey
  │     AES-GCM  → plaintext JSON
  │     GCM tag mismatch? → throw → return INVALID("decryption_failed")
  │
  ├── age = now - instruction.signedAt
  │     age > 86400s → return INVALID("stale_packet")
  │     age < -300s  → return INVALID("future_dated")
  │
  └── settlement.settle(instruction, hash, bridgeNodeId, hopCount)
        @Transactional:
          sender.balance -= amount
          receiver.balance += amount
          save both accounts    ← @Version provides optimistic lock
          save Transaction{status=SETTLED}
        insufficient funds?
          save Transaction{status=REJECTED}
          return REJECTED (not INVALID — instruction was valid, just broke)
```

---

## The Three Hard Problems

### 1. Confidentiality and Integrity Over Untrusted Hops

**Problem:** Stranger's phone carries your ₹500 payment. Nothing stops them from reading the payload or modifying it.

**Solution:** The payload never exists in cleartext outside the sender and the server. Intermediaries hold an opaque blob. If they flip even one bit, the GCM authentication tag verification fails on the server and the packet is rejected entirely. There is no path from "modified ciphertext" to "successfully processed but with a different amount."

### 2. Exactly-Once Settlement Despite Concurrent Duplicate Delivery

**Problem:** Three bridge nodes hold the same packet. They all get internet simultaneously. All three POST to the backend within milliseconds. Naive processing: sender debited 3x.

**Solution:**
```
Thread-1: putIfAbsent(hash, t1) → returns null  → FIRST CLAIMER → proceeds
Thread-2: putIfAbsent(hash, t2) → returns t1    → DUPLICATE → dropped immediately
Thread-3: putIfAbsent(hash, t3) → returns t1    → DUPLICATE → dropped immediately
```
`ConcurrentHashMap.putIfAbsent` is a single atomic operation in the JVM. No lock, no race, no window where two threads both see `null`. Exactly one thread wins.

### 3. Replay Attacks

**Problem:** An attacker captures a ciphertext and replays it a week later.

**Solution — Layer 1:** `signedAt` is embedded inside the encrypted payload. The server rejects packets older than 24 hours. The attacker cannot change `signedAt` — any mutation invalidates the GCM tag.

**Solution — Layer 2:** Even within the 24-hour window, the idempotency cache catches a replay. The ciphertext is byte-identical to the original delivery, so its hash is identical, so `claim()` returns false.

**Solution — Layer 3:** Even if Alice legitimately sends Bob ₹100 twice in the same session, the nonce (UUID) differs each time → different ciphertext → different hash → both settle correctly. The system distinguishes legitimate repeated payments from replays.

---

## Cryptography Deep Dive

### Why Hybrid Encryption?

RSA-2048 with OAEP-SHA256 can encrypt at most ~190 bytes of plaintext. A `PaymentInstruction` serialized to JSON is already ~200–300 bytes. Include a device certificate or digital signature and you're at 500+ bytes. RSA alone fails.

The solution is identical to what TLS, PGP, and Signal use:

```
┌─────────────────────────────────────────────────────────────────┐
│  AES-256 Key (32 bytes, random, per-packet)                     │
│       │                                                         │
│       ├──[RSA-OAEP-SHA256]──▶ 256 bytes (fits in RSA budget)   │
│       │                                                         │
│       └──[AES-256-GCM]──────▶ encrypt JSON payload             │
│                               (any size, authenticated)         │
└─────────────────────────────────────────────────────────────────┘

Wire format (base64-encoded):
[ 256 bytes: RSA-encrypted AES key ]
[ 12 bytes:  GCM IV (random, per-packet) ]
[ N bytes:   AES-GCM ciphertext + 16-byte auth tag ]
```

### Why AES-GCM Specifically?

GCM (Galois/Counter Mode) provides **authenticated encryption with associated data (AEAD)**. It produces a 16-byte authentication tag computed over the entire ciphertext. Any mutation of any byte in the ciphertext or the tag causes `AEADBadTagException` on decryption. This eliminates:

- Bit-flipping attacks (change amount from ₹500 to ₹5)
- Truncation attacks (remove the last byte)
- Substitution attacks (splice in bytes from another ciphertext)

### Why the Ciphertext Hash Is the Idempotency Key

```
packetId   → outer cleartext field → any intermediate can rewrite it
             → NOT suitable as dedup key

plaintext  → requires decryption first (expensive RSA)
             → want to dedup BEFORE spending CPU on crypto
             → NOT suitable as early gate

ciphertext → immutable (any change = GCM tag mismatch = rejection)
             → identical for duplicate deliveries (same bytes)
             → hashable before decryption
             → PERFECT idempotency key
```

---

## Idempotency Design

```java
// IdempotencyService.java — the core of exactly-once semantics

public boolean claim(String packetHash) {
    Instant now = Instant.now();
    Instant prev = seen.putIfAbsent(packetHash, now);
    return prev == null;  // true = first and only claimer
}
```

This is a direct port of the Redis pattern `SET key NX EX ttl`. The contract:

- **Atomicity:** `ConcurrentHashMap.putIfAbsent` is a single CAS operation. Concurrent calls with the same key have one winner, deterministically.
- **TTL:** A `@Scheduled` eviction task removes entries older than `idempotency-ttl-seconds` (default: 86400). This prevents unbounded memory growth.
- **Defense in depth:** Even if the cache is cold (restarted, evicted), the `transactions` table has `UNIQUE INDEX (packet_hash)`. The DB will reject a duplicate insert with a constraint violation, which propagates as an exception and prevents double-settlement.
- **Third layer:** `@Version` on `Account` provides optimistic locking. Two concurrent settlements for the same sender would result in one `OptimisticLockException` — a fail-safe that prevents corrupted balances even if both somehow passed the idempotency check.

**In production:** Replace `ConcurrentHashMap` with:
```
SET packetHash NX EX 86400
```
Identical semantics, now distributed across all backend replicas.

---

## Settlement Pipeline

```java
@Transactional  // ← entire method is one DB transaction
public Transaction settle(PaymentInstruction instruction, ...) {

    Account sender   = accountRepo.findById(instruction.getSenderVpa()).orElseThrow();
    Account receiver = accountRepo.findById(instruction.getReceiverVpa()).orElseThrow();

    if (sender.getBalance().compareTo(amount) < 0) {
        return recordRejected(...);  // writes REJECTED tx, does NOT debit
    }

    sender.setBalance(sender.getBalance().subtract(amount));   // debit
    receiver.setBalance(receiver.getBalance().add(amount));    // credit
    accountRepo.save(sender);     // @Version bumped here → concurrent write = OptimisticLockException
    accountRepo.save(receiver);

    // write ledger entry
    Transaction tx = buildTransaction(Status.SETTLED, ...);
    return transactionRepo.save(tx);
}
```

Key properties:
- If the debit succeeds but the credit throws, the entire `@Transactional` block rolls back. The ledger is always consistent.
- `REJECTED` settlement is still a ledger entry — auditable, visible in the dashboard, not silently swallowed.
- `hopCount` and `bridgeNodeId` are recorded on every transaction for analytics ("which mesh paths actually settle payments?").

---

## Security Considerations

| Threat | Mitigation |
|---|---|
| Intermediate reads payment details | AES-256-GCM: payload is ciphertext to all intermediates |
| Intermediate modifies amount or VPA | GCM auth tag: any mutation → `AEADBadTagException` → INVALID |
| Attacker replays an old ciphertext | `signedAt` freshness check (24h window) + idempotency cache |
| Attacker rewrites `packetId` to bypass dedup | Dedup key is `SHA-256(ciphertext)`, not `packetId` |
| Three bridges deliver simultaneously | Atomic `putIfAbsent` — exactly one wins |
| Double-settlement if cache is cold | `UNIQUE INDEX (packet_hash)` in DB |
| Concurrent balance corruption | `@Version` optimistic locking on `Account` |
| Stale packet replayed within freshness window | Idempotency cache catches identical ciphertext |
| Future-dated packet (clock skew attack) | `signedAt > now + 5min` → rejected as `future_dated` |
| Private key compromise | In prod: HSM/KMS. In demo: ephemeral keypair per startup |
| Unauthorized bridge node ingestion | In prod: mTLS or signed bridge certificates. In demo: open |

---

## Dashboard Walkthrough

<img width="902" height="925" alt="Screenshot 2026-05-07 140050" src="https://github.com/user-attachments/assets/8c630aab-15d7-49d5-b770-61ca54750c08" />

The dashboard at `http://localhost:8080` drives the entire demo with four interactions:

**Step 1 — Compose Payment**
Select sender VPA, receiver VPA, amount, PIN. Click **Inject**. The backend simulates the sender's phone: builds, encrypts, and injects the `MeshPacket` into `phone-alice`. Watch the Mesh Devices panel — `phone-alice` now holds 1 packet.

**Step 2 — Gossip Rounds**
Click **Run Gossip Round** one or more times. Each round propagates packets across all virtual devices, decrementing TTL per hop. After one round, all five devices hold the packet. This simulates people walking past each other in a basement.

**Step 3 — Bridge Upload**
Click **Upload to Backend**. `phone-bridge` is the only device with `hasInternet=true`. It POSTs all held packets to `/api/bridge/ingest` in parallel. Watch the Balances panel — money moves. Watch the Transaction Ledger — a new row appears with outcome `SETTLED`.

**Step 4 — Reset**
Click **Reset Mesh + Cache** to wipe the mesh state and idempotency cache. Balances are not reset (the DB persists within the session). To re-seed balances, restart the server.

**Activity Log**
Every user action appends timestamped entries. Bridge upload outcomes (`SETTLED`, `DUPLICATE_DROPPED`, `INVALID`) appear here in real-time.

<img width="798" height="940" alt="image" src="https://github.com/user-attachments/assets/492d6943-109e-403a-9015-315ae373ef72" />

---

## API Reference

### Core Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the interactive dashboard |
| `GET` | `/api/v1/server-key` | Server's RSA-2048 public key (base64 + metadata) |
| `GET` | `/api/v1/accounts` | All accounts with current balances |
| `GET` | `/api/v1/transactions` | Last 20 transactions (newest first) |
| `GET` | `/api/v1/mesh/state` | State of every virtual device (packet counts, IDs, internet status) |

### Simulation Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/demo/send` | Simulates sender phone: encrypt + inject packet into mesh |
| `POST` | `/api/v1/mesh/gossip` | Run one gossip round across all virtual devices |
| `POST` | `/api/v1/mesh/flush` | Bridge nodes with internet upload packets to backend (parallel) |
| `POST` | `/api/v1/mesh/reset` | Clear all device packet queues + idempotency cache |

### Production Endpoint

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/bridge/ingest` | Real endpoint a bridge node calls. Full pipeline: hash → claim → decrypt → freshness → settle |

### Request: `POST /api/v1/demo/send`

```json
{
  "senderVpa":   "ShubhamTiwari@demo",
  "receiverVpa": "Sarvesh@demo",
  "amount":      500.00,
  "pin":         "1234",
  "ttl":         5,
  "startDevice": "phone-alice"
}
```

Response:
```json
{
  "packetId":         "550e8400-e29b-41d4-a716-446655440000",
  "ciphertextPreview":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoA...",
  "ttl":              5,
  "injectedAt":       "phone-alice"
}
```

### Request: `POST /api/v1/bridge/ingest`

```http
POST /api/v1/bridge/ingest
Content-Type: application/json
X-Bridge-Node-Id: phone-bridge-42
X-Hop-Count: 3

{
  "packetId":  "550e8400-e29b-41d4-a716-446655440000",
  "ttl":       2,
  "createdAt": 1730000000000,
  "ciphertext": "<base64-blob>"
}
```

Response:
```json
{
  "outcome":       "SETTLED",
  "packetHash":    "a3f8c9d2e1b4...",
  "reason":        null,
  "transactionId": 42
}
```

Possible `outcome` values: `SETTLED`, `REJECTED` (insufficient funds), `DUPLICATE_DROPPED`, `INVALID`.

### H2 Console

Browse the live database at `http://localhost:8080/h2-console`
- JDBC URL: `jdbc:h2:mem:upimesh`
- Username: *(empty)*
- Password: *(empty)*

---

## Folder Structure

```
upi-offline-mesh/
│
├── pom.xml                                    Maven build (Spring Boot 3.3, Java 17)
├── mvnw / mvnw.cmd                            Maven wrapper — no local Maven needed
│
└── src/
    ├── main/
    │   ├── resources/
    │   │   ├── application.yaml               H2 config, port, TTL properties
    │   │   └── templates/
    │   │       └── dashboard.html             Interactive dark-theme demo UI (Thymeleaf)
    │   │
    │   └── java/com/upimesh/
    │       │
    │       ├── UpiWithoutInternetApplication.java   Spring Boot entry point
    │       │
    │       ├── config/
    │       │   └── AppConfig.java             @EnableScheduling for cache eviction
    │       │
    │       ├── entity/                        ── Domain layer
    │       │   ├── Account.java               JPA entity; @Version = optimistic lock
    │       │   ├── Transaction.java           Settled/rejected tx record; unique on packetHash
    │       │   ├── MeshPacket.java            Wire format for mesh propagation
    │       │   ├── PaymentInstruction.java    Decrypted payload (inner structure)
    │       │   └── VirtualDevice.java         Simulated phone; holds packets in ConcurrentHashMap
    │       │
    │       ├── enums/
    │       │   └── Status.java                SETTLED | REJECTED
    │       │
    │       ├── repository/
    │       │   ├── AccountRepository.java     Spring Data JPA
    │       │   └── TransactionRepository.java findTop20ByOrderByIdDesc
    │       │
    │       ├── crypto/                        ── Cryptography layer
    │       │   ├── ServerKeyHolder.java        Generates RSA-2048 keypair on startup; exposes public key
    │       │   └── HybridCryptoService.java    RSA-OAEP + AES-256-GCM encrypt/decrypt; ciphertext hash
    │       │
    │       ├── service/                       ── Business logic
    │       │   ├── DemoService.java            Seeds accounts; simulates sender phone
    │       │   ├── MeshSimulatorService.java   Gossip protocol; virtual device management
    │       │   ├── IdempotencyService.java     Atomic ConcurrentHashMap claim; scheduled eviction
    │       │   ├── BridgeIngestionService.java Full ingestion pipeline (THE core service)
    │       │   └── SettlementService.java      @Transactional debit + credit + ledger
    │       │
    │       └── controller/
    │           ├── ApiController.java          All REST endpoints
    │           └── DashboardController.java    GET / → dashboard.html
    │
    └── test/
        └── java/com/upimesh/
            └── UpiWithoutInternetApplicationTests.java   Context load + concurrency tests
```

---

## Running Locally

### Prerequisites

- **JDK 17+** — the only hard requirement. Nothing else needs to be installed.
    - Windows: `winget install EclipseAdoptium.Temurin.17.JDK`
    - Mac: `brew install temurin@17`
    - Linux: `sudo apt install openjdk-17-jdk`

Verify: `java -version` should print `17` or higher.

### Start the server

**Windows:**
```cmd
.\mvnw.cmd spring-boot:run
```

**Mac / Linux:**
```bash
chmod +x mvnw
./mvnw spring-boot:run
```

First run downloads Maven (~10 MB) and all dependencies (~80 MB). Subsequent starts take ~5 seconds.

When you see:
```
Started UpiWithoutInternetApplication in 3.4 seconds
```
open **http://localhost:8080**.

### Stop

`Ctrl+C` in the terminal.

### Change the port

In `src/main/resources/application.yaml`:
```yaml
server:
  port: 9090   # change from 8080
```

### Configuration reference

```yaml
upi:
  mesh:
    idempotency-ttl-seconds: 86400   # how long to remember a packet hash (1 day)
    packet-max-age-seconds:  86400   # max age of signedAt before rejecting as stale
```

---

## Running Tests

```bash
./mvnw test
```

### Test coverage

**`contextLoads`** — basic Spring context wiring sanity check.

**Encryption round-trip** — encrypts a `PaymentInstruction` with the server's public key, decrypts with the private key, asserts field-level equality. Validates the hybrid crypto scheme is symmetric and lossless.

**Tamper rejection** — encrypts a valid payload, then flips a byte in the middle of the base64 ciphertext, feeds it to `BridgeIngestionService.ingest()`, and asserts the outcome is `INVALID` with reason `decryption_failed`. Validates that GCM auth tag catches mutation.

**Concurrent exactly-once settlement** — creates one `MeshPacket`, then fires 3 threads simultaneously at `BridgeIngestionService.ingest()`:
```
Thread-1 ─┐
Thread-2 ──┼─── ingest(samePacket) ──▶ exactly one SETTLED
Thread-3 ─┘                            exactly two DUPLICATE_DROPPED
                                        sender balance reduced exactly once
```
This is the headline test. It exercises `ConcurrentHashMap.putIfAbsent` under genuine JVM-level concurrency.

---

## Production-Grade Improvements

This is an architectural demo. Moving it toward production involves the following concrete changes:

### Infrastructure

| Demo | Production |
|---|---|
| H2 in-memory DB | PostgreSQL (primary + read replicas) |
| `ConcurrentHashMap` idempotency | Redis Cluster with `SET NX EX 86400` |
| Single JVM instance | Horizontally scaled behind a load balancer |
| RSA keypair generated on startup | Private key in AWS KMS / HashiCorp Vault HSM |
| H2 console exposed | Disabled entirely |
| No rate limiting | Per-bridge-node rate limit (token bucket), per-sender velocity cap |
| Console logging | Structured JSON logs → SIEM (Datadog / Splunk); alert on `INVALID` spike |

### Security Hardening

```
/api/bridge/ingest:
  - Mutual TLS: bridge nodes hold signed client certificates issued by the backend CA
  - Or: HMAC-signed request with bridge node's private key, verified on server
  - Revocation: bridge certificates have short TTL, refreshed when online

Sender phones:
  - Server's public key cached on device during initial online session
  - Public key has an expiry; refreshed when connectivity is available
  - Key pinning to prevent MITM during the cache phase
```

### Mesh Protocol

```
Demo:    In-process gossip simulation (everyone talks to everyone in one step)

Prod:    Android: BLE GATT + Wi-Fi Direct
         - Discovery: BLE advertising / scanning (even in background, within Android limits)
         - Transfer: BLE GATT write for small packets, Wi-Fi Direct for larger ones
         - Dedup at hop layer: each device maintains a bloom filter of seen packetIds
           (bloom filter = compact, probabilistic, no false negatives for dedup)
         - Battery: exponential backoff on re-advertising when no peers found
```

### Settlement

```
Demo:    Simple ledger in H2, settlement service owns the balance

Prod:    - Integration with NPCI / bank core API for actual fund movement
         - Offline UPI Lite model: pre-funded hardware wallet on device gives
           cryptographic proof of available funds without a live balance check
         - Two-phase settlement: provisional debit on ingest, final on bank ACK
         - Chargeback / dispute handling
         - Regulatory audit trail (RBI compliance)
```

### Observability

```yaml
# Production metrics to expose:
packets_ingested_total{outcome="SETTLED|DUPLICATE_DROPPED|INVALID"}
packet_age_seconds_histogram         # distribution of signedAt lag
bridge_upload_hop_count_histogram    # how many hops before reaching internet
settlement_latency_ms_histogram      # time from signedAt to settledAt
idempotency_cache_hit_rate           # % of ingestions that are duplicates
```

---

## Real-World Constraints and Limitations

These are not implementation bugs — they are inherent properties of offline payment systems. Knowing them makes the project's scope credible.

### 1. No proof of funds at signing time

When the sender's phone generates the packet, there is no live balance check. If Shubham has ₹500 and signs a ₹500 payment for Sarvesh in basement A, then walks to basement B and signs another ₹500 for Rushabh, both packets propagate independently. Whichever reaches the backend first settles; the second is `REJECTED`. Rushabh or Sarvesh is short ₹500 with no recourse.

**This is why UPI Lite uses a pre-funded hardware-backed offline wallet** — the available funds are locked at offline wallet creation time and cryptographically committed. This demo does not implement UPI Lite semantics.

### 2. Double-spend is possible by a motivated attacker

A sender with ₹500 can sign the same ₹500 payment to two different recipients with different nonces. Both packets are valid. Only one settles. The sender gets one "free" transaction. Mitigating this requires real-time fund reservation at signing, which requires connectivity — a fundamental tension.

### 3. Bluetooth reliability on modern mobile OSes

Android throttles background BLE scanning since API 26. iOS does not support BLE peripheral mode for arbitrary data transfer from third-party apps in the background. Real-world gossip propagation requires foreground app usage or a custom BLE stack — non-trivial. This demo sidesteps the problem entirely.

### 4. Privacy and regulatory surface

An intermediary device carries a metadata trail: "payment packet was in my vicinity at this time." Even though the payload is encrypted, the existence and timing of the packet is observable. This has KYC, AML, and privacy implications that would need regulatory sign-off before production deployment in India.

### 5. Receiver confirmation latency

The receiver has no real-time confirmation. They see a "sent" screen on the sender's phone, but settlement happens asynchronously — possibly minutes or hours later. The receiver can't confirm receipt until both are online. For merchant payments this is commercially difficult.

---

## Future Enhancements

These represent the gap between this demo and a production-viable system:

**Short-term (technical completeness)**
- Android client (Kotlin) — the sender phone side of the flow running on real hardware
- BLE GATT integration — real Bluetooth gossip between physical devices
- Bloom filter at the hop layer — efficient packet dedup without storing all packetIds
- Pre-funded offline wallet — cryptographic proof of funds at signing time

**Medium-term (production readiness)**
- Redis for distributed idempotency cache
- mTLS on `/bridge/ingest` with bridge certificate management
- PostgreSQL + Flyway migrations
- Prometheus metrics + Grafana dashboard for mesh analytics
- Signed bridge uploads with request-level HMAC

**Long-term (ecosystem)**
- NPCI / bank core integration for real fund settlement
- Regulatory sandbox testing (RBI innovation sandbox)
- UPI Lite protocol compatibility
- Multi-currency / cross-border mesh extension
- Zero-knowledge proof of balance (pay without revealing exact balance to intermediaries)

---

## License

Demo / portfolio code. No license. Use it however you want for learning, reference, or extension. Attribution appreciated but not required.

---

*Built to demonstrate that exactly-once settlement over an adversarial, unreliable gossip mesh is an engineering problem — not an impossible one.*
