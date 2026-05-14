package com.upimesh.service;

import com.upimesh.crypto.HybridCryptoService;
import com.upimesh.entity.MeshPacket;
import com.upimesh.entity.PaymentInstruction;
import com.upimesh.entity.Transaction;
import java.time.Instant;

import com.upimesh.enums.Status;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Orchestrates the full server-side pipeline for one inbound packet from a bridge node:
 *
 * <p>1. Hash the ciphertext. 2. Try to claim that hash via the idempotency cache. - If already
 * claimed: this is a duplicate. Drop it. 3. Decrypt the ciphertext with the server's private key. -
 * If decryption fails: tampered or junk. Reject. 4. Check freshness — reject if signedAt is too old
 * (replay protection). 5. Hand off to SettlementService for the actual debit/credit.
 */
@Service
@Slf4j
public class BridgeIngestionService {

  @Autowired private HybridCryptoService crypto;
  @Autowired private IdempotencyService idempotency;
  @Autowired private SettlementService settlement;

  @Value("${upi.mesh.packet-max-age-seconds:86400}")
  private long maxAgeSeconds;

  public IngestResult ingest(MeshPacket packet, String bridgeNodeId, int hopCount) {
    try {
      String packetHash = crypto.hashCiphertext(packet.getCiphertext());

      // 1. Idempotency check
      if (!idempotency.claim(packetHash)) {
        log.info("DUPLICATE packet {} from bridge {} — dropped",
                packetHash.substring(0, 12) + "...", bridgeNodeId);
        return IngestResult.duplicate(packetHash);
      }

      // 2. Decrypt
      PaymentInstruction instruction;
      try {
        instruction = crypto.decrypt(packet.getCiphertext());
      } catch (Exception e) {
        log.warn("Decryption failed for packet {}: {}",
                packetHash.substring(0, 12) + "...", e.getMessage());
        return IngestResult.invalid(packetHash, "decryption_failed");
      }

      // 3. Freshness check
      long ageSeconds = (Instant.now().toEpochMilli() - instruction.getSignedAt()) / 1000;
      if (ageSeconds > maxAgeSeconds) {
        log.warn("Packet {} too old ({}s)", packetHash.substring(0, 12) + "...", ageSeconds);
        return IngestResult.invalid(packetHash, "stale_packet");
      }
      if (ageSeconds < -300) {
        return IngestResult.invalid(packetHash, "future_dated");
      }

      int maxHops = instruction.getMaxHops();
      if (maxHops > 0 && hopCount > maxHops) {
        log.warn("Packet {} exceeded maxHops: allowed={} actual={}",
                packetHash.substring(0, 12) + "...", maxHops, hopCount);
        return IngestResult.invalid(packetHash,
                "exceeded_max_hops: allowed=" + maxHops + " actual=" + hopCount);
      }


      // 4. Settle
      Transaction tx = settlement.settle(instruction, packetHash, bridgeNodeId, hopCount);

      if (tx.getStatus() == com.upimesh.enums.Status.REJECTED) {
        return IngestResult.invalid(packetHash, "settlement_rejected");
      }

      return IngestResult.settled(packetHash, tx);

    } catch (Exception e) {
      log.error("Ingestion error: {}", e.getMessage(), e);
      return IngestResult.invalid("?", "internal_error: " + e.getMessage());
    }
  }

  public record IngestResult(String outcome, String packetHash, String reason, Long transactionId) {
    public static IngestResult settled(String hash, Transaction tx) {
      return new IngestResult("SETTLED", hash, null, tx.getId());
    }
    public static IngestResult duplicate(String hash) {
      return new IngestResult("DUPLICATE_DROPPED", hash, null, null);
    }
    public static IngestResult invalid(String hash, String reason) {
      return new IngestResult("INVALID", hash, reason, null);
    }
  }
}
