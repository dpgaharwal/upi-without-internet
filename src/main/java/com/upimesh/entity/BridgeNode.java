package com.upimesh.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Ek registered bridge node ki identity.
 *
 * <p>Jo bhi device {@code /api/bridge/ingest} call karna chahta hai use pehle
 * {@code POST /api/bridge/register} se register karna padta hai. Server us node ka
 * {@code hmacSecret} store karta hai.
 *
 * <p>Har upload pe bridge ciphertext ka {@code HMAC-SHA256(ciphertext, hmacSecret)}
 * compute karke {@code X-Bridge-Signature} header mein bhejta hai. Server same HMAC
 * recompute karke match karta hai. Agar mismatch ho ya nodeId unknown ho to upload
 * reject ho jaata hai.
 *
 * <p>Revocation: {@code revoked = true} set karne ke baad us bridge ke saare future
 * uploads 403 se reject honge bina processing ke.
 *
 * <p>Note: Yahan symmetric HMAC shared secret use kiya gaya hai simplicity ke liye.
 * Production mein asymmetric keys (bridge private, server public) zyada secure honge.
 */
@Entity
@Table(name = "bridge_nodes")
@Getter
@Setter
@NoArgsConstructor
public class BridgeNode {

  /** Bridge ka unique identifier. {@code X-Bridge-Node-Id} header mein aata hai. */
  @Id
  @Column(nullable = false, length = 128)
  private String nodeId;

  /**
   * HMAC-SHA256 shared secret, base64-encoded, minimum 32 bytes.
   * Bridge yahi secret use karke har upload sign karta hai.
   * Server yahi stored secret se verify karta hai.
   */
  @Column(nullable = false, length = 512)
  private String hmacSecret;

  /** Jab bridge ne register kiya tha. */
  @Column(nullable = false)
  private Instant registeredAt;

  /**
   * Agar {@code true} hai to is bridge ke saare uploads reject honge.
   * Compromised bridges ko revoke karne ke liye use hota hai.
   */
  @Column(nullable = false)
  private boolean revoked = false;

  public BridgeNode(String nodeId, String hmacSecret, Instant registeredAt) {
    this.nodeId = nodeId;
    this.hmacSecret = hmacSecret;
    this.registeredAt = registeredAt;
    this.revoked = false;
  }
}