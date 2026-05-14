package com.upimesh.entity;

import com.upimesh.enums.TokenStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Index;
import java.math.BigDecimal;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A signed offline spend token.
 *
 * <p>When a user goes online they call POST /api/token/issue. The server:
 *   1. Checks the sender has sufficient balance.
 *   2. Creates a SpendToken that RESERVES that amount (balance is not yet debited —
 *      reservation is tracked in the token row).
 *   3. Returns the token's nonce to the client. The client embeds the nonce inside
 *      the PaymentInstruction before encrypting, so the nonce lives inside the
 *      ciphertext — tamper-proof.
 *
 * <p>On ingest the server calls SpendTokenService.consume(nonce, senderVpa, amount).
 * Exactly one thread wins (unique index on nonce + status=ACTIVE check). If the
 * token is already CONSUMED or EXPIRED, settlement is rejected.
 *
 * <p>This kills the double-spend scenario: Shubham has ₹500. He issues a token for
 * ₹500, embeds the nonce in packet-A (to Sarvesh) and tries to embed the SAME nonce
 * in packet-B (to Rushabh). Packet-A settles → token CONSUMED. Packet-B arrives →
 * consume() returns false → REJECTED("spend_token_invalid").
 *
 * <p>If he issues two separate tokens, each for ₹500, that requires two online
 * sessions where the server checks balance twice — the second issuance fails if
 * balance is already reserved.
 */
@Entity
@Table(
        name = "spend_tokens",
        indexes = {
                @Index(name = "idx_token_nonce", columnList = "nonce", unique = true),
                @Index(name = "idx_token_vpa_status", columnList = "senderVpa, status")
        })
@Getter
@Setter
@NoArgsConstructor
public class SpendToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The secret value embedded inside the encrypted PaymentInstruction.
     * UUID, globally unique. This is what the server checks on ingest.
     */
    @Column(nullable = false, unique = true, length = 36)
    private String nonce;

    @Column(nullable = false)
    private String senderVpa;

    /**
     * The amount this token authorises. The server checks that the actual
     * payment amount matches exactly — a token for ₹500 cannot settle ₹501.
     */
    @Column(nullable = false, precision = 19, scale = 2)
    private BigDecimal reservedAmount;

    /** When the token was issued. */
    @Column(nullable = false)
    private Instant issuedAt;

    /**
     * Tokens expire after this time. Default TTL is 24 hours (same as packet
     * max-age), so an expired token and a stale packet are rejected together.
     */
    @Column(nullable = false)
    private Instant expiresAt;

    /** ACTIVE → CONSUMED (settled) or EXPIRED (eviction job). */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenStatus status;

    /** Set when the token is consumed during settlement. */
    @Column
    private Instant consumedAt;

    /** The packetHash that consumed this token (for audit trail). */
    @Column(length = 64)
    private String consumedByPacketHash;

    public SpendToken(String nonce, String senderVpa, BigDecimal reservedAmount,
                      Instant issuedAt, Instant expiresAt) {
        this.nonce = nonce;
        this.senderVpa = senderVpa;
        this.reservedAmount = reservedAmount;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = TokenStatus.ACTIVE;
    }
}