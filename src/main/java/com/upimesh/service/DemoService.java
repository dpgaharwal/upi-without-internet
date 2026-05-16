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
 * Demo helper service — startup pe accounts seed karta hai aur simulated
 * "sender phone packet banata hai" flow implement karta hai.
 *
 * <p>Real app mein packet sender ke phone pe local banta aur server ka public key
 * cached hota device pe. Yahan server khud packet banata hai demo ke liye.
 */
@Service
@Slf4j
public class DemoService {

  @Autowired private AccountRepository accounts;
  @Autowired private HybridCryptoService crypto;
  @Autowired private ServerKeyHolder serverKey;

  /**
   * Startup pe 4 demo accounts seed karo agar DB empty hai.
   * Demo run karne ke liye koi manual setup nahi chahiye.
   */
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
   * Simulated "sender phone" ek encrypted mesh packet banata hai.
   *
   * <p>{@link com.upimesh.entity.PaymentInstruction} construct hoti hai jisme
   * {@code spendTokenNonce} aur {@code maxHops} dono encrypted payload ke andar
   * commit hote hain — bahar se tamper nahi ho sakte.
   *
   * <p>{@code maxHops} default 5 hai (TTL ke barabar). Sender kam value set kare to
   * packet sirf utne hops mein server tak pahunchne pe valid hoga — agar TTL bahar se
   * reset kiya gaya tab bhi yeh encrypted check fail karega.
   *
   * @param senderVpa      sender ka VPA
   * @param receiverVpa    receiver ka VPA
   * @param amount         amount rupees mein
   * @param pin            UPI PIN (SHA-256 hash andar jayega)
   * @param ttl            outer cleartext TTL — gossip flood control ke liye
   * @param spendTokenNonce server-issued token ka nonce (double-spend prevention)
   * @param maxHops        encrypted max hops commitment
   * @return encrypted {@link MeshPacket} jo mesh mein inject hone ke liye ready hai
   * @throws Exception agar encryption fail ho
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

  /**
   * Input string ka SHA-256 hex digest compute karo — PIN hashing ke liye.
   *
   * @param input hash karne wali string
   * @return lowercase hex SHA-256 digest
   * @throws Exception agar SHA-256 algorithm available nahi hai
   */
  private String sha256Hex(String input) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(input.getBytes());
    StringBuilder hex = new StringBuilder();
    for (byte b : hash) hex.append(String.format("%02x", b));
    return hex.toString();
  }
}