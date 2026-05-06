package com.upimesh.controller;

import com.upimesh.crypto.ServerKeyHolder;
import com.upimesh.entity.Account;
import com.upimesh.entity.MeshPacket;
import com.upimesh.entity.Transaction;
import com.upimesh.entity.VirtualDevice;
import com.upimesh.repository.AccountRepository;
import com.upimesh.repository.TransactionRepository;
import com.upimesh.service.BridgeIngestionService;
import com.upimesh.service.DemoService;
import com.upimesh.service.IdempotencyService;
import com.upimesh.service.MeshSimulatorService;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public REST surface.
 *
 * <p>The endpoints split into three groups: /api/server-key → so simulated senders can fetch the
 * server's public key /api/mesh/* → simulator endpoints (inject, gossip, flush) /api/bridge/ingest
 * → THE real production endpoint a real bridge node would hit /api/accounts, /api/transactions →
 * for the dashboard
 */
@RestController
@RequestMapping("/api/v1")
public class ApiController {

  @Autowired private ServerKeyHolder serverKey;
  @Autowired private DemoService demo;
  @Autowired private MeshSimulatorService mesh;
  @Autowired private BridgeIngestionService bridge;
  @Autowired private AccountRepository accountRepo;
  @Autowired private TransactionRepository txRepo;
  @Autowired private IdempotencyService idempotency;

  // ================Server Key===========================
  @GetMapping("/server-key")
  public Map<String, String> getServerPublicKey() {
    return Map.of(
        "publicKey", serverKey.getPublicKeyBase64(),
        "algorithm", "RSA-2048 / OAEP-SHA256",
        "hybridScheme", "RSA-OAEP encrypts an AES-256-GCM session key");
  }

  /**
   * Demo helper: build a packet on the server (simulating a sender phone) and inject it into the
   * mesh at the given device.
   */
  @PostMapping("/demo/send")
  public ResponseEntity<?> demoSend(@RequestBody DemoSendRequest req) throws Exception {

    MeshPacket packet =
        demo.createPacket(
            req.senderVpa, req.receiverVpa, req.amount, req.pin, req.ttl == null ? 5 : req.ttl);

    String startDevice = req.startDevice == null ? "phone-shubham" : req.startDevice;
    mesh.inject(startDevice, packet);

    return ResponseEntity.ok(
        Map.of(
            "packetId",
            packet.getPacketId(),
            "ciphertextPreview",
            packet.getCiphertext().substring(0, 64) + "...",
            "ttl",
            packet.getTtl(),
            "injectedAt",
            startDevice));
  }

  public static class DemoSendRequest {
    public String senderVpa;
    public String receiverVpa;
    public BigDecimal amount;
    public String pin;
    public Integer ttl;
    public String startDevice;
  }

  @GetMapping("/mesh/state")
  public Map<String, Object> meshState() {
    List<Map<String, Object>> deviceData = new ArrayList<>();
    for (VirtualDevice d : mesh.getDevices()) {
      deviceData.add(
          Map.of(
              "deviceId", d.getDeviceId(),
              "hasInternet", d.hasInternet(),
              "packetCount", d.packetCount(),
              "packetIds",
                  d.getHeldPackets().stream().map(p -> p.getPacketId().substring(0, 8)).toList()));
    }
    return Map.of("devices", deviceData, "idempotencyCacheSize", idempotency.size());
  }

  @PostMapping("/mesh/gossip")
  public Map<String, Object> meshGossip() {
    MeshSimulatorService.GossipResult r = mesh.gossipOnce();
    return Map.of(
        "transfers", r.transfers(),
        "deviceCounts", r.deviceCounts());
  }

  @PostMapping("/mesh/flush")
  public Map<String, Object> meshFlush() {
    List<MeshSimulatorService.BridgeUpload> uploads = mesh.collectBridgeUploads();

    List<Map<String, Object>> results = new ArrayList<>();

    uploads.parallelStream()
        .forEach(
            up -> {
              BridgeIngestionService.IngestResult r =
                  bridge.ingest(up.packet(), up.bridgeNodeId(), 5 - up.packet().getTtl());
              synchronized (results) {
                results.add(
                    Map.of(
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
      @RequestHeader(value = "X-Bridge-Node-Id", defaultValue = "unknown") String bridgeNodeId,
      @RequestHeader(value = "X-Hop-Count", defaultValue = "0") int hopCount) {

    BridgeIngestionService.IngestResult r = bridge.ingest(packet, bridgeNodeId, hopCount);
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
