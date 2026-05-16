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
 * Pura public REST surface — dashboard aur bridge nodes dono yahi use karte hain.
 *
 * <p>Endpoints teen groups mein hain:
 * <ul>
 *   <li>{@code /api/server-key} — simulated sender devices server ki public key fetch karte hain.</li>
 *   <li>{@code /api/token/*} — spend token issue, status check, active list.</li>
 *   <li>{@code /api/demo/send} — simulated payment packet banao aur mesh mein inject karo.</li>
 *   <li>{@code /api/mesh/*} — simulator endpoints: state, gossip, flush, reset, ack.</li>
 *   <li>{@code /api/bridge/*} — bridge node registration, ingest, revoke, list.</li>
 *   <li>{@code /api/accounts}, {@code /api/transactions} — dashboard display ke liye.</li>
 *   <li>{@code /api/acks/*} — receiver acknowledgement create, gossip, verify, query.</li>
 * </ul>
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

  /**
   * Server ki RSA-2048 public key return karo.
   * Simulated sender devices ise payment encrypt karne ke liye use karte hain.
   *
   * @return public key base64 mein, algorithm info ke saath
   */
  @GetMapping("/server-key")
  public Map<String, String> getServerPublicKey() {
    return Map.of(
            "publicKey", serverKey.getPublicKeyBase64(),
            "algorithm", "RSA-2048 / OAEP-SHA256",
            "hybridScheme", "RSA-OAEP encrypts an AES-256-GCM session key");
  }

  /**
   * Sender ke liye ek spend token issue karo.
   * Online session mein call hota hai — nonce milta hai jo payment mein embed hota hai.
   *
   * <p>{@code POST /api/token/issue}
   * Body: {@code { "senderVpa": "ShubhamTiwari@demo", "amount": 500.00 }}
   *
   * @param req sender VPA aur amount
   * @return nonce aur expiry (success), ya reason (fail)
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
   * Nonce se token ki current status check karo — dashboard ke liye.
   *
   * <p>{@code GET /api/token/status/{nonce}}
   *
   * @param nonce token ka nonce
   * @return token details ya 404
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
   * Ek sender ke saare active tokens list karo.
   *
   * <p>{@code GET /api/token/active/{senderVpa}}
   *
   * @param senderVpa sender ka VPA
   * @return active tokens ki list
   */
  @GetMapping("/token/active/{senderVpa}")
  public List<SpendToken> activeTokens(@PathVariable String senderVpa) {
    return spendTokenService.getTokensForSender(senderVpa);
  }

  /**
   * Simulated payment packet banao aur mesh mein inject karo.
   *
   * <p>{@code POST /api/demo/send}
   *
   * @param req payment details — sender, receiver, amount, PIN, optional token nonce
   * @return packet ID, ciphertext preview, aur injection info
   */
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

  /** Token issue request body — sender VPA aur amount. */
  public static class TokenIssueRequest {
    public String senderVpa;
    public BigDecimal amount;
  }

  /** Demo send request body — poori payment details. */
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

  /** Mesh ka current state return karo — har device pe packet count aur IDs. */
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

  /** Ek gossip round simulate karo — saare devices ek doosre ko packets bhejte hain. */
  @PostMapping("/mesh/gossip")
  public Map<String, Object> meshGossip() {
    MeshSimulatorService.GossipResult r = mesh.gossipOnce();
    return Map.of("transfers", r.transfers(), "deviceCounts", r.deviceCounts());
  }

  /**
   * Internet-connected devices ke packets server ko upload karo.
   * Har upload pe bridge auth verify hoti hai pehle.
   */
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

  /** Mesh aur idempotency cache reset karo — fresh demo start ke liye. */
  @PostMapping("/mesh/reset")
  public Map<String, Object> meshReset() {
    mesh.resetMesh();
    idempotency.clear();
    ackService.clear();
    return Map.of("status", "mesh and idempotency cache cleared");
  }

  /**
   * Real bridge node yeh endpoint call karta hai packet upload karne ke liye.
   * Bridge auth verify hoti hai pehle — unknown ya revoked bridge 403 paata hai.
   *
   * <p>{@code POST /api/bridge/ingest}
   * Headers: {@code X-Bridge-Node-Id}, {@code X-Bridge-Signature}
   *
   * @param packet      mesh packet body
   * @param bridgeNodeId bridge ka node ID header se
   * @param signature   HMAC signature header se
   * @return ingestion result — {@code SETTLED}, {@code DUPLICATE_DROPPED}, ya {@code INVALID}
   */
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
   * Bridge node register karo — ek baar online mein call hota hai.
   * Bridge apna secret generate karta hai, register karta hai, aur phir
   * har upload pe usi secret se sign karta hai.
   *
   * <p>{@code POST /api/bridge/register}
   * Body: {@code { "nodeId": "bridge-prod-1", "hmacSecret": "<base64 >=32 bytes>" }}
   *
   * @param req nodeId aur hmacSecret
   * @return registration result
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
   * Bridge node revoke karo — iske baad us bridge ke saare uploads 403 se reject honge.
   *
   * <p>{@code POST /api/bridge/revoke/{nodeId}}
   *
   * @param nodeId revoke karne wala bridge ID
   * @return revocation result
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
   * Saare registered bridges list karo — active aur revoked dono.
   *
   * <p>{@code GET /api/bridge/nodes}
   *
   * @return bridge nodes ki list
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
   * Receiver device ek packet ke liye signed ack create karo.
   * Real system mein yeh automatically BLE pe packet aane par hota.
   * Yahan dashboard se manually call karte hain simulate karne ke liye.
   *
   * <p>{@code POST /api/mesh/ack/create}
   * Body: {@code { "packetId": "...", "receiverVpa": "Sarvesh@demo" }}
   *
   * @param req packetId aur receiverVpa
   * @return created ack ka preview
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
   * Acks ko mesh mein reverse direction mein propagate karo (receiver se sender ki taraf).
   *
   * <p>{@code POST /api/mesh/ack/gossip}
   *
   * @return kitne ack transfers hue
   */
  @PostMapping("/mesh/ack/gossip")
  public Map<String, Object> gossipAcks() {
    int transfers = ackService.gossipAcks();
    return Map.of("ackTransfers", transfers);
  }

  /**
   * Ek packet ke saare signed acks return karo.
   * Sender yeh call karke confirm karta hai ki payment receive hui.
   * Har ack pe signature validity bhi check hoti hai.
   *
   * <p>{@code GET /api/acks/{packetId}}
   *
   * @param packetId jis packet ke acks chahiye
   * @return acks ki list signature validity ke saath
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
   * Ek specific ack signature verify karo — sender authenticity confirm karne ke liye.
   *
   * <p>{@code POST /api/acks/verify}
   * Body: AckPacket JSON
   *
   * @param ack verify karne wala ack packet
   * @return signature validity result
   */
  @PostMapping("/acks/verify")
  public Map<String, Object> verifyAck(@RequestBody AckPacket ack) {
    boolean valid = ackService.verifyAck(ack);
    return Map.of(
            "packetId", ack.getPacketId(),
            "receiverVpa", ack.getReceiverVpa(),
            "signatureValid", valid);
  }


  /** Dashboard ke liye saare demo accounts aur unke balances return karo. */
  @GetMapping("/accounts")
  public List<Account> listAccounts() {
    return accountRepo.findAll();
  }

  /** Dashboard ke liye latest 20 transactions return karo — newest pehle. */
  @GetMapping("/transactions")
  public List<Transaction> listTransactions() {
    return txRepo.findTop20ByOrderByIdDesc();
  }

  /** Bridge registration request body. */
  public static class BridgeRegisterRequest {
    public String nodeId;
    public String hmacSecret;
  }

  /** Ack create request body. */
  public static class AckCreateRequest {
    public String packetId;
    public String receiverVpa;
  }
}
