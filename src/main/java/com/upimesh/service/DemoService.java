package com.upimesh.service;

import com.upimesh.crypto.HybridCryptoService;
import com.upimesh.crypto.ServerKeyHolder;
import com.upimesh.entity.Account;
import com.upimesh.entity.MeshPacket;
import com.upimesh.entity.PaymentInstruction;
import com.upimesh.repository.AccountRepository;
import jakarta.annotation.PostConstruct;
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Helper service that: - seeds demo accounts on startup - simulates "sender phone creates an
 * encrypted packet" flow
 */
@Service
@Slf4j
public class DemoService {

  @Autowired private AccountRepository accounts;
  @Autowired private HybridCryptoService crypto;
  @Autowired private ServerKeyHolder serverKey;

  @PostConstruct
  public void seedAccount() {
    if (accounts.count() == 0) {
      accounts.save(new Account("ShubhamTiwari@demo", "Shubham Tiwari", new BigDecimal("500.00")));
      accounts.save(new Account("Sarvesh@demo", "Sarvesh", new BigDecimal("70000.00")));
      accounts.save(new Account("Rushabh@demo", "Rushabh", new BigDecimal("80000.00")));
      accounts.save(new Account("Sudarshan@demo", "Sudarshan", new BigDecimal("90000.00")));
      log.info("Seeded 4 demo accounts");
    }
  }

  /**
   * UPDATED
   * - accepts spendTokenNonce
   * - accepts maxHops — embedded inside encrypted payload
   *
   * maxHops default is 5 (same as TTL). Sender can set lower value
   * e.g. maxHops=2 means packet is only valid if it reached server
   * within 2 hops. More hops = rejected even if TTL was tampered.
   */
  public MeshPacket createPacket(
          String senderVpa, String receiverVpa,
          BigDecimal amount, String pin,
          int ttl, String spendTokenNonce,
          int maxHops) throws Exception {

    PaymentInstruction instruction = new PaymentInstruction(
            senderVpa,
            receiverVpa,
            amount,
            sha256Hex(pin),
            UUID.randomUUID().toString(),
            Instant.now().toEpochMilli(),
            spendTokenNonce,
            maxHops);               // committed inside encrypted blob

    String ciphertext = crypto.encrypt(instruction, serverKey.getPublicKey());

    MeshPacket packet = new MeshPacket();
    packet.setPacketId(UUID.randomUUID().toString());
    packet.setTtl(ttl);
    packet.setCreatedAt(Instant.now().toEpochMilli());
    packet.setCiphertext(ciphertext);
    return packet;
  }

  private String sha256Hex(String input) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(input.getBytes());
    StringBuilder hex = new StringBuilder();
    for (byte b : hash) hex.append(String.format("%02x", b));
    return hex.toString();
  }
}