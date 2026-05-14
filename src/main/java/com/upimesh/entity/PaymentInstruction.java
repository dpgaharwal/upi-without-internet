package com.upimesh.entity;

import java.math.BigDecimal;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * The actual payment instruction. After the server decrypts MeshPacket.ciphertext, it gets one of
 * these.
 *
 * <p>Critical fields for security: - nonce: a UUID unique to this payment. Even if everything else
 * were identical for two legitimate payments (alice sends bob ₹100 twice), the nonces differ, so
 * the resulting ciphertexts and their hashes also differ. - signedAt: lets the server reject stale
 * packets ("freshness window"). Without this, an attacker who got the ciphertext could replay it
 * weeks later. - pinHash: in a real system the user enters a UPI PIN; we'd verify it against a hash
 * held by the bank. Here we just record it for realism.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PaymentInstruction {

  private String senderVpa;
  private String receiverVpa;
  private BigDecimal amount;
  private String pinHash;
  private String nonce; // UUID, unique per payment intent
  private Long signedAt; // epoch millis, when sender signed
  private String spendTokenNonce; // token nonce issued by server before going offline
}
