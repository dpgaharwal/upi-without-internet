package com.upimesh.entity;

import java.math.BigDecimal;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Actual payment instruction jo server decrypt karke padhta hai.
 *
 * <p>Yeh pura object AES-256-GCM se encrypt hoke {@link MeshPacket#getCiphertext()} ke
 * andar baith jaata hai. Intermediate devices ise kabhi nahi dekh sakte.
 *
 * <p>Security ke liye critical fields:
 * <ul>
 *   <li>{@code nonce} — UUID, har payment ke liye alag. Do alag payments mein same
 *       sab kuch ho tab bhi nonce alag hoga, isliye ciphertext aur uska hash alag
 *       hoga — dono settle ho jayenge correctly.</li>
 *   <li>{@code signedAt} — server purane packets reject karta hai (default 24 ghante
 *       se zyada purana packet invalid). Replay attack ko rok ta hai.</li>
 *   <li>{@code spendTokenNonce} — server ne offline jaane se pehle jo token issue kiya
 *       tha uska nonce. Bina valid token ke settlement reject hoti hai.</li>
 *   <li>{@code maxHops} — sender ne encrypt karke andar rakha hua TTL commitment.
 *       Bahar ke {@code ttl} field ko koi bhi reset kar sakta hai, lekin yeh andar
 *       wala server verify karta hai ki packet zyada time tak zinda nahi raha.</li>
 * </ul>
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PaymentInstruction {

  /** Sender ka VPA, jaise {@code ShubhamTiwari@demo}. */
  private String senderVpa;

  /** Receiver ka VPA, jaise {@code Sarvesh@demo}. */
  private String receiverVpa;

  /** Rupees mein amount. Settlement ke waqt exactly yahi amount transfer hota hai. */
  private BigDecimal amount;

  /**
   * UPI PIN ka SHA-256 hash. Real system mein bank ke saath verify hota.
   * Yahan sirf realism ke liye record kiya jaata hai.
   */
  private String pinHash;

  /**
   * UUID — is specific payment intent ka unique identifier.
   * Same sender same amount ko do baar bheje to bhi nonce alag hoga
   * isliye dono packets alag hash mein settle honge.
   */
  private String nonce;

  /** Epoch milliseconds — sender ne packet kab sign kiya. Replay attack rokne ke liye. */
  private Long signedAt;

  /**
   * Server-issued spend token ka nonce. Online session mein liya gaya tha.
   * Yeh encrypted payload ke andar hai isliye tamper-proof hai.
   * Bina valid token ke {@link com.upimesh.service.SettlementService} reject kar deta hai.
   */
  private String spendTokenNonce;

  /**
   * Sender-committed maximum hops. Encrypted andar hai isliye koi bahar se badal nahi sakta.
   * Server check karta hai: {@code ageSeconds <= maxHops * perHopSeconds}.
   * Zyada time lag gaya matlab packet artificially zinda rakha gaya — reject.
   */
  private int maxHops;
}
