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
      BridgeIngestionService.IngestResult r =
              bridge.ingest(up.packet(), up.bridgeNodeId());
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
    return Map.of("status", "mesh and idempotency cache cleared");
  }

  @PostMapping("/bridge/ingest")
  public ResponseEntity<?> ingest(
          @RequestBody MeshPacket packet,
          @RequestHeader(value = "X-Bridge-Node-Id", defaultValue = "unknown") String bridgeNodeId) {
    // X-Hop-Count header REMOVED — untrusted, ignored
    BridgeIngestionService.IngestResult r = bridge.ingest(packet, bridgeNodeId);
    return ResponseEntity.ok(r);
  }

  @GetMapping("/accounts")
  public List<Account> listAccounts() {
    return accountRepo.findAll();
  }

  @GetMapping("/transactions")
  public List<Transaction> listTransactions() {
    return txRepo.findTop20ByOrderByIdDesc();
  }
}
