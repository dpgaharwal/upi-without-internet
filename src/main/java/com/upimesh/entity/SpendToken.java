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
 * Ek offline spend token — double-spend prevention ka core mechanism.
 *
 * <p>Jab user offline jaane se pehle online hota hai, server ek token issue karta hai.
 * Server us waqt check karta hai ki {@code balance - already_reserved >= requestedAmount}.
 * Token ka {@code nonce} sender ke phone ko milta hai jo usse {@link PaymentInstruction}
 * ke andar encrypt karke embed karta hai.
 *
 * <p>Settlement ke waqt server {@code consume()} call karta hai. {@code nonce} pe unique
 * index hai aur {@code status = ACTIVE} check hai isliye exactly ek hi thread consume
 * kar sakta hai — doosra ya to {@code CONSUMED} status dekhega ya constraint violation
 * paayega. Dono cases mein doosra settle nahi hoga.
 *
 * <p>Lifecycle:
 * <pre>
 *   ACTIVE  --[payment settled]-->  CONSUMED
 *   ACTIVE  --[time expired]----->  EXPIRED
 * </pre>
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
     * Encrypted PaymentInstruction ke andar embed hone wala secret value.
     * UUID, globally unique. Server ingest ke waqt yahi check karta hai.
     */
    @Column(nullable = false, unique = true, length = 36)
    private String nonce;

    /** Sender ka VPA jisne yeh token issue karwaya. */
    @Column(nullable = false)
    private String senderVpa;

    /**
     * Is token se authorize hone wala exact amount.
     * Server check karta hai ki actual payment amount exactly match kare —
     * ₹500 ka token ₹501 settle nahi kar sakta.
     */
    @Column(nullable = false, precision = 19, scale = 2)
    private BigDecimal reservedAmount;

    /** Jab token issue hua tha. */
    @Column(nullable = false)
    private Instant issuedAt;

    /**
     * Is time ke baad token expire ho jaata hai. Default 24 ghante —
     * packet ki max-age ke barabar, isliye dono saath reject honge.
     */
    @Column(nullable = false)
    private Instant expiresAt;

    /** Token ki current state: {@code ACTIVE}, {@code CONSUMED}, ya {@code EXPIRED}. */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenStatus status;

    /** Jab token settlement mein consume hua — audit ke liye. */
    @Column
    private Instant consumedAt;

    /** Wo packetHash jisne token consume kiya — traceability ke liye. */
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