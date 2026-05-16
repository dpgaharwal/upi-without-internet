package com.upimesh.entity;

import com.upimesh.enums.Status;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Ek settled ya rejected payment transaction ka permanent record.
 *
 * <p>{@code packetHash} pe unique index hai jo database-level duplicate settlement
 * rok ta hai — idempotency cache ke baad bhi ek extra safety net.
 */
@Entity
@Table(
    name = "transactions",
    indexes = {@Index(name = "idx_packet_hash", columnList = "packetHash", unique = true)})
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Transaction {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  /** SHA-256 hex of encrypted packet — idempotency key jo duplicate settlement rokta hai. */
  @Column(nullable = false, unique = true, length = 64)
  private String packetHash;

  /** Sender ka VPA jo payment bhej raha tha. */
  @Column(nullable = false)
  private String senderVpa;

  /** Receiver ka VPA jisko paisa mila. */
  @Column(nullable = false)
  private String receiverVpa;

  /** Kitna amount transfer hua ya hone ki koshish ki. */
  @Column(nullable = false, precision = 19, scale = 2)
  private BigDecimal amount;

  /** Sender ne kab offline packet sign kiya tha — original timestamp. */
  @Column(nullable = false)
  private Instant signedAt;

  /** Backend ne kab packet process kiya — settlement timestamp. */
  @Column(nullable = false)
  private Instant settledAt;

  /** Kaun sa mesh node packet server tak laya (bridge ka device ID). */
  @Column(nullable = false)
  private String bridgeNodeId;

  /** Kitne devices se hokar packet guzra server tak pahunchne se pehle. */
  @Column(nullable = false)
  private int hopCount;

  /** {@code SETTLED} ya {@code REJECTED} — final outcome. */
  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private Status status;
}
