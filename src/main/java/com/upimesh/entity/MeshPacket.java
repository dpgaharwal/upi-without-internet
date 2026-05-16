package com.upimesh.entity;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Wo packet jo phone se phone tak hop karta hai mesh mein.
 *
 * <p>Intermediate devices sirf outer fields ({@code packetId}, {@code ttl},
 * {@code createdAt}) padhte hain — routing aur dedup ke liye. {@code ciphertext}
 * unke liye opaque hai kyunki woh server ki public key se encrypt hai.
 *
 * <p>Outer fields tamper ho sakte hain (koi bhi {@code packetId} badal sakta
 * hai), isliye server idempotency ke liye {@code packetId} ki jagah
 * {@code SHA-256(ciphertext)} use karta hai. Ciphertext mein koi bhi badlaav
 * GCM authentication tag fail kar deta hai — is wajah se ciphertext ka hash
 * tamper-proof dedup key hai.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class MeshPacket {

  /** Packet ka unique ID. Routing ke liye use hota hai, lekin idempotency ke liye nahi. */
  @NotBlank private String packetId;

  /**
   * Hops ka counter. Har intermediate device ek se kam karta hai.
   * Zero ho jaye to packet aage nahi bheja jaata — flood control ke liye.
   */
  @Min(0)
  private int ttl;

  /** Jab packet create hua tha us waqt ka epoch milliseconds. */
  @NotNull private Long createdAt;

  /**
   * Encrypted payment instruction.
   * Format: [256 bytes RSA-encrypted AES key][12 bytes IV][AES-GCM ciphertext + 16 bytes auth tag].
   * Koi bhi bit flip hone par decryption fail ho jaati hai.
   */
  @NotBlank private String ciphertext;
}
