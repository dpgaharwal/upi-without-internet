package com.upimesh.controller;

import com.upimesh.crypto.ServerKeyHolder;
import com.upimesh.entity.*;
import com.upimesh.repository.AccountRepository;
import com.upimesh.repository.TransactionRepository;
import com.upimesh.service.*;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.upimesh.entity.AckPacket;
import com.upimesh.service.AckService;
import com.upimesh.service.BridgeAuthService;

/**
 * Public REST surface.
 *
 * <p>The endpoints split into three groups: /api/server-key → so simulated senders can fetch the
 * server's public key /api/mesh/* → simulator endpoints (inject, gossip, flush) /api/bridge/ingest
 * → THE real production endpoint a real bridge node would hit /api/accounts, /api/transactions →
 * for the dashboard
 */
@RestController
@RequestMapping("/api")
public class ApiController {

  @Autowired private ServerKeyHolder serverKey;
  @Autowired private DemoService demo;
  @Autowired private MeshSimulatorService mesh;
  @Autowired private BridgeIngestionService bridge;
  @Autowired private AccountRepository accountRepo;
  @Autowired private TransactionRepository txRepo;
  @Autowired private IdempotencyService idempotency;
  @Autowired private SpendTokenService spendTokenService;
  @Autowired private AckService ackService;
  @Autowired private BridgeAuthService bridgeAuthService;

  @GetMapping("/server-key")
  public Map<String, String> getServerPublicKey() {
    return Map.of(
            "publicKey", serverKey.getPublicKeyBase64(),
            "algorithm", "RSA-2048 / OAEP-SHA256",
            "hybridScheme", "RSA-OAEP encrypts an AES-256-GCM session key");
  }

  /**
   * Issue a spend token.
   * The client calls this while online, gets the nonce back,
   * then embeds it in every PaymentInstruction created offline.
   *
   * POST /api/token/issue
   * Body: { "senderVpa": "ShubhamTiwari@demo", "amount": 500.00 }
   */
  @PostMapping("/token/issue")
  public ResponseEntity<?> issueToken(@RequestBody TokenIssueRequest req) {
    SpendTokenService.IssueResult result =
            spendTokenService.issue(req.senderVpa, req.amount);

    if (!result.success()) {
      return ResponseEntity.badRequest().body(Map.of(
              "success", false,
              "reason", result.reason()));
    }

    return ResponseEntity.ok(Map.of(
            "success", true,
            "nonce", result.nonce(),
            "senderVpa", req.senderVpa,
            "reservedAmount", req.amount,
            "expiresAt", result.expiresAt().toString()));
  }

  /**
   * Check the current status of a token by its nonce.
   * GET /api/token/status/{nonce}
   */
  @GetMapping("/token/status/{nonce}")
  public ResponseEntity<?> tokenStatus(@PathVariable String nonce) {
    SpendToken token = spendTokenService.getByNonce(nonce);
    if (token == null) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(Map.of(
            "nonce", token.getNonce(),
            "senderVpa", token.getSenderVpa(),
            "reservedAmount", token.getReservedAmount(),
            "status", token.getStatus().name(),
            "issuedAt", token.getIssuedAt().toString(),
            "expiresAt", token.getExpiresAt().toString(),
            "consumedAt", token.getConsumedAt() == null ? "" : token.getConsumedAt().toString(),
            "consumedByPacketHash", token.getConsumedByPacketHash() == null
                    ? "" : token.getConsumedByPacketHash()));
  }

  /**
   * List all ACTIVE tokens for a sender.
   * GET /api/token/active/{senderVpa}
   */
  @GetMapping("/token/active/{senderVpa}")
  public List<SpendToken> activeTokens(@PathVariable String senderVpa) {
    return spendTokenService.getTokensForSender(senderVpa);
  }

  // ── Demo send (updated to accept spendTokenNonce) ─────────────────────────

  @PostMapping("/demo/send")
  public ResponseEntity<?> demoSend(@RequestBody DemoSendRequest req) throws Exception {

    int maxHops = req.maxHops == null ? 5 : req.maxHops;

    MeshPacket packet = demo.createPacket(
            req.senderVpa,
            req.receiverVpa,
            req.amount,
            req.pin,
            req.ttl == null ? 5 : req.ttl,
            req.spendTokenNonce,
            maxHops);

    String startDevice = req.startDevice == null ? "phone-shubham" : req.startDevice;
    mesh.inject(startDevice, packet);

    return ResponseEntity.ok(Map.of(
            "packetId",         packet.getPacketId(),
            "ciphertextPreview", packet.getCiphertext().substring(0, 64) + "...",
            "ttl",              packet.getTtl(),
            "injectedAt",       startDevice,
            "spendTokenNonce",  req.spendTokenNonce == null ? "none" :
                    req.spendTokenNonce.substring(0, 8) + "...",
            "maxHops",          maxHops));
  }

  //  Request/response shapes
  public static class TokenIssueRequest {
    public String senderVpa;
    public BigDecimal amount;
  }

  public static class DemoSendRequest {
    public String senderVpa;
    public String receiverVpa;
    public BigDecimal amount;
    public String pin;
    public Integer ttl;
    public String startDevice;
    public String spendTokenNonce;
    public Integer maxHops;
  }

  // Mesh endpoints

  @GetMapping("/mesh/state")
  public Map<String, Object> meshState() {
    List<Map<String, Object>> deviceData = new ArrayList<>();
    for (VirtualDevice d : mesh.getDevices()) {
      deviceData.add(Map.of(
              "deviceId", d.getDeviceId(),
              "hasInternet", d.hasInternet(),
              "packetCount", d.packetCount(),
              "packetIds", d.getHeldPackets().stream()
                      .map(p -> p.getPacketId().substring(0, 8)).toList()));
    }
    return Map.of("devices", deviceData,
            "idempotencyCacheSize", idempotency.size());
  }

  @PostMapping("/mesh/gossip")
  public Map<String, Object> meshGossip() {
    MeshSimulatorService.GossipResult r = mesh.gossipOnce();
    return Map.of("transfers", r.transfers(), "deviceCounts", r.deviceCounts());
  }

  @PostMapping("/mesh/flush")
  public Map<String, Object> meshFlush() {
    List<MeshSimulatorService.BridgeUpload> uploads = mesh.collectBridgeUploads();
    List<Map<String, Object>> results = new ArrayList<>();

    uploads.parallelStream().forEach(up -> {
      // P7: verify bridge signature before ingesting
      BridgeAuthService.VerifyResult auth = bridgeAuthService.verifyUpload(
              up.bridgeNodeId(), up.hmacSignature(), up.packet().getCiphertext());

      BridgeIngestionService.IngestResult r;
      if (!auth.success()) {
        r = BridgeIngestionService.IngestResult.invalid(
                up.packet().getPacketId(), "bridge_auth_failed: " + auth.reason());
      } else {
        r = bridge.ingest(up.packet(), up.bridgeNodeId());
      }

      synchronized (results) {
        results.add(Map.of(
                "bridgeNode", up.bridgeNodeId(),
                "packetId", up.packet().getPacketId().substring(0, 8),
                "outcome", r.outcome(),
                "reason", r.reason() == null ? "" : r.reason(),
                "transactionId", r.transactionId() == null ? -1 : r.transactionId()));
      }
    });

    return Map.of("uploadsAttempted", uploads.size(), "results", results);
  }

  @PostMapping("/mesh/reset")
  public Map<String, Object> meshReset() {
    mesh.resetMesh();
    idempotency.clear();
    ackService.clear();
    return Map.of("status", "mesh and idempotency cache cleared");
  }

  @PostMapping("/bridge/ingest")
  public ResponseEntity<?> ingest(
          @RequestBody MeshPacket packet,
          @RequestHeader(value = "X-Bridge-Node-Id", defaultValue = "unknown") String bridgeNodeId,
          @RequestHeader(value = "X-Bridge-Signature", defaultValue = "") String signature) {

    // P7: Verify bridge identity + signature BEFORE any processing
    BridgeAuthService.VerifyResult auth =
            bridgeAuthService.verifyUpload(bridgeNodeId, signature, packet.getCiphertext());

    if (!auth.success()) {
      return ResponseEntity.status(403).body(Map.of(
              "outcome", "REJECTED",
              "reason", "bridge_auth_failed: " + auth.reason()));
    }

    BridgeIngestionService.IngestResult r = bridge.ingest(packet, bridgeNodeId);
    return ResponseEntity.ok(r);
  }

  /**
   * Register a bridge node.
   * POST /api/bridge/register
   * Body: { "nodeId": "bridge-prod-1", "hmacSecret": "<base64 of >=32 bytes>" }
   *
   * The bridge generates its own secret (e.g. SecureRandom 32 bytes → base64),
   * registers once while online, then uses the same secret to sign every upload.
   */
  @PostMapping("/bridge/register")
  public ResponseEntity<?> registerBridge(@RequestBody BridgeRegisterRequest req) {
    BridgeAuthService.RegisterResult result =
            bridgeAuthService.register(req.nodeId, req.hmacSecret);

    if (!result.success()) {
      return ResponseEntity.badRequest().body(Map.of(
              "success", false,
              "reason", result.reason()));
    }

    return ResponseEntity.ok(Map.of(
            "success", true,
            "nodeId", result.node().getNodeId(),
            "registeredAt", result.node().getRegisteredAt().toString(),
            "alreadyExisted", result.alreadyExisted()));
  }

  /**
   * Revoke a bridge node — all future uploads from it will be rejected.
   * POST /api/bridge/revoke/{nodeId}
   */
  @PostMapping("/bridge/revoke/{nodeId}")
  public ResponseEntity<?> revokeBridge(@PathVariable String nodeId) {
    BridgeAuthService.RevokeResult result = bridgeAuthService.revoke(nodeId);
    if (!result.success()) {
      return ResponseEntity.badRequest().body(Map.of(
              "success", false, "reason", result.reason()));
    }
    return ResponseEntity.ok(Map.of("success", true, "revokedNodeId", nodeId));
  }

  /**
   * List all registered bridges (active + revoked).
   * GET /api/bridge/nodes
   */
  @GetMapping("/bridge/nodes")
  public ResponseEntity<?> listBridges() {
    return ResponseEntity.ok(bridgeAuthService.listAll().stream().map(n -> Map.of(
            "nodeId", n.getNodeId(),
            "registeredAt", n.getRegisteredAt().toString(),
            "revoked", n.isRevoked()
    )).toList());
  }

  /**
   * Receiver device calls this to create + store a signed ack for a packet it received.
   * POST /api/mesh/ack/create
   * Body: { "packetId": "...", "receiverVpa": "Sarvesh@demo" }
   *
   * In real system: called automatically on the receiver's phone when a packet arrives via BLE.
   * Here: called manually from dashboard to simulate receiver acknowledging.
   */
  @PostMapping("/mesh/ack/create")
  public ResponseEntity<?> createAck(@RequestBody AckCreateRequest req) {
    AckPacket ack = ackService.createAck(req.packetId, req.receiverVpa);
    if (ack == null) {
      return ResponseEntity.badRequest().body(Map.of(
              "success", false,
              "reason", "no_keypair_for_vpa: " + req.receiverVpa));
    }
    return ResponseEntity.ok(Map.of(
            "success", true,
            "packetId", ack.getPacketId(),
            "receiverVpa", ack.getReceiverVpa(),
            "timestamp", ack.getTimestamp(),
            "signaturePreview", ack.getSignature().substring(0, 16) + "...",
            "ttl", ack.getTtl()));
  }

  /**
   * Propagate acks one gossip round back through the mesh (receiver → sender direction).
   * POST /api/mesh/ack/gossip
   */
  @PostMapping("/mesh/ack/gossip")
  public Map<String, Object> gossipAcks() {
    int transfers = ackService.gossipAcks();
    return Map.of("ackTransfers", transfers);
  }

  /**
   * Get all acks for a specific packet (sender uses this to confirm payment was received).
   * GET /api/acks/{packetId}
   */
  @GetMapping("/acks/{packetId}")
  public ResponseEntity<?> getAcks(@PathVariable String packetId) {
    List<AckPacket> acks = ackService.getAcksForPacket(packetId);
    if (acks.isEmpty()) {
      return ResponseEntity.ok(Map.of("packetId", packetId, "acks", List.of()));
    }
    return ResponseEntity.ok(Map.of(
            "packetId", packetId,
            "ackCount", acks.size(),
            "acks", acks.stream().map(a -> Map.of(
                    "receiverVpa", a.getReceiverVpa(),
                    "timestamp", a.getTimestamp(),
                    "ttl", a.getTtl(),
                    "signatureValid", ackService.verifyAck(a),
                    "signaturePreview", a.getSignature().substring(0, 16) + "..."
            )).toList()
    ));
  }

  /**
   * Verify a specific ack signature. Used by sender to confirm authenticity.
   * POST /api/acks/verify
   * Body: AckPacket JSON
   */
  @PostMapping("/acks/verify")
  public Map<String, Object> verifyAck(@RequestBody AckPacket ack) {
    boolean valid = ackService.verifyAck(ack);
    return Map.of(
            "packetId", ack.getPacketId(),
            "receiverVpa", ack.getReceiverVpa(),
            "signatureValid", valid);
  }


  @GetMapping("/accounts")
  public List<Account> listAccounts() {
    return accountRepo.findAll();
  }

  @GetMapping("/transactions")
  public List<Transaction> listTransactions() {
    return txRepo.findTop20ByOrderByIdDesc();
  }

  public static class BridgeRegisterRequest {
    public String nodeId;
    public String hmacSecret;
  }

  public static class AckCreateRequest {
    public String packetId;
    public String receiverVpa;
  }
}
