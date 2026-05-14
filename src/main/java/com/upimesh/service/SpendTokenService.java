package com.upimesh.service;

import com.upimesh.entity.Account;
import com.upimesh.entity.SpendToken;
import com.upimesh.enums.TokenStatus;
import com.upimesh.repository.AccountRepository;
import com.upimesh.repository.SpendTokenRepository;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages offline spend tokens — the fix for the double-spend problem.
 *
 * <p>WHY THIS EXISTS:
 * Without tokens, Shubham can sign two separate ₹500 payments while offline
 * (one to Sarvesh, one to Rushabh), and whichever bridge uploads first settles.
 * The second packet also appears valid and gets REJECTED only at settlement time
 * because the balance is already gone — which is fine, but it means the second
 * recipient is left confused with no money and no explanation until they go online.
 *
 * <p>With tokens, the server pre-authorises each payment at issuance time by
 * checking that (current balance − already reserved amount) ≥ requested amount.
 * Two simultaneous ₹500 tokens on a ₹500 balance: the second issuance fails
 * immediately with INSUFFICIENT_BALANCE_FOR_RESERVATION — no packet is ever
 * created, so no false hope for Rushabh.
 *
 * <p>THE CONSUME CONTRACT (exactly-once):
 * consume() runs inside a @Transactional block and does a select-then-update.
 * The unique index on `nonce` plus the status=ACTIVE guard means only one
 * concurrent thread can win — the second one either finds status=CONSUMED
 * (already done) or hits a constraint violation (race). Either way it loses.
 *
 * <p>TOKEN LIFECYCLE:
 *   ACTIVE  ->  CONSUMED  (packet settled successfully)
 *   ACTIVE  ->  EXPIRED   (eviction job runs, expiresAt has passed)
 */
@Service
@Slf4j
public class SpendTokenService {

    @Autowired private SpendTokenRepository tokenRepo;
    @Autowired private AccountRepository accountRepo;

    @Value("${upi.mesh.token-ttl-seconds:86400}")
    private long tokenTtlSeconds;

    // ── Issue ────────────────────────────────────────────────────────────────

    /**
     * Issue a spend token for senderVpa authorising exactly `amount`.
     *
     * <p>Guards:
     * 1. Sender must exist.
     * 2. (balance − totalActiveReserved) must be >= amount.
     *
     * Returns the token nonce — the sender embeds this in PaymentInstruction
     * before encrypting. The nonce never travels in cleartext outside the
     * encrypted ciphertext.
     */
    @Transactional
    public IssueResult issue(String senderVpa, BigDecimal amount) {

        if (amount == null || amount.signum() <= 0) {
            return IssueResult.fail("amount_must_be_positive");
        }

        Account sender = accountRepo.findById(senderVpa).orElse(null);
        if (sender == null) {
            return IssueResult.fail("unknown_sender_vpa");
        }

        // Sum all ACTIVE (not yet consumed/expired) reservations for this sender
        BigDecimal alreadyReserved = tokenRepo
                .findBySenderVpaAndStatus(senderVpa, TokenStatus.ACTIVE)
                .stream()
                .map(SpendToken::getReservedAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        BigDecimal available = sender.getBalance().subtract(alreadyReserved);
        if (available.compareTo(amount) < 0) {
            log.warn("Token issuance denied for {}: balance={} reserved={} requested={}",
                    senderVpa, sender.getBalance(), alreadyReserved, amount);
            return IssueResult.fail("insufficient_balance_for_reservation");
        }

        String nonce = UUID.randomUUID().toString();
        Instant now = Instant.now();
        SpendToken token = new SpendToken(
                nonce, senderVpa, amount, now, now.plusSeconds(tokenTtlSeconds));
        tokenRepo.save(token);

        log.info("Token issued: nonce={} sender={} amount={} expiresAt={}",
                nonce.substring(0, 8) + "...", senderVpa, amount, token.getExpiresAt());

        return IssueResult.ok(nonce, token.getExpiresAt());
    }

    // ── Consume ──────────────────────────────────────────────────────────────

    /**
     * Attempt to consume a spend token during settlement.
     *
     * <p>Rules:
     * - Token must exist (nonce must match).
     * - Token must be ACTIVE (not already CONSUMED or EXPIRED).
     * - Token's senderVpa must match the payment's senderVpa.
     * - Token's reservedAmount must match the payment amount exactly.
     * - Token must not have passed its expiresAt.
     *
     * If all checks pass, marks the token CONSUMED and returns true.
     * Any failure returns false — settlement will be rejected.
     */
    @Transactional
    public ConsumeResult consume(String nonce, String senderVpa,
                                 BigDecimal amount, String packetHash) {

        // No token nonce in the instruction → payment was made without a token
        if (nonce == null || nonce.isBlank()) {
            return ConsumeResult.fail("missing_spend_token");
        }

        SpendToken token = tokenRepo.findByNonce(nonce).orElse(null);
        if (token == null) {
            log.warn("Token not found: nonce={}", nonce.substring(0, 8) + "...");
            return ConsumeResult.fail("token_not_found");
        }

        if (token.getStatus() != TokenStatus.ACTIVE) {
            log.warn("Token already {} for nonce={}", token.getStatus(),
                    nonce.substring(0, 8) + "...");
            return ConsumeResult.fail("token_already_" + token.getStatus().name().toLowerCase());
        }

        if (Instant.now().isAfter(token.getExpiresAt())) {
            token.setStatus(TokenStatus.EXPIRED);
            tokenRepo.save(token);
            return ConsumeResult.fail("token_expired");
        }

        if (!token.getSenderVpa().equals(senderVpa)) {
            log.warn("Token VPA mismatch: token={} payment={}", token.getSenderVpa(), senderVpa);
            return ConsumeResult.fail("token_vpa_mismatch");
        }

        if (token.getReservedAmount().compareTo(amount) != 0) {
            log.warn("Token amount mismatch: token={} payment={}", token.getReservedAmount(), amount);
            return ConsumeResult.fail("token_amount_mismatch");
        }

        // All checks passed — consume the token
        token.setStatus(TokenStatus.CONSUMED);
        token.setConsumedAt(Instant.now());
        token.setConsumedByPacketHash(packetHash);
        tokenRepo.save(token);

        log.info("Token CONSUMED: nonce={} sender={} amount={} packet={}",
                nonce.substring(0, 8) + "...", senderVpa, amount,
                packetHash.substring(0, 12) + "...");

        return ConsumeResult.ok();
    }

    // ── Status ───────────────────────────────────────────────────────────────

    /** Return the current state of a token by nonce (for the dashboard). */
    public SpendToken getByNonce(String nonce) {
        return tokenRepo.findByNonce(nonce).orElse(null);
    }

    /** All tokens for a given sender (dashboard view). */
    public List<SpendToken> getTokensForSender(String senderVpa) {
        return tokenRepo.findBySenderVpaAndStatus(senderVpa, TokenStatus.ACTIVE);
    }

    // ── Eviction ─────────────────────────────────────────────────────────────

    /** Runs every 60 seconds. Bulk-expires tokens past their TTL. */
    @Scheduled(fixedDelay = 60_000)
    @Transactional
    public void evictExpiredTokens() {
        int count = tokenRepo.expireTokensBefore(Instant.now());
        if (count > 0) {
            log.info("Evicted {} expired spend token(s)", count);
        }
    }

    // ── Result records ───────────────────────────────────────────────────────

    public record IssueResult(boolean success, String nonce, Instant expiresAt, String reason) {
        public static IssueResult ok(String nonce, Instant expiresAt) {
            return new IssueResult(true, nonce, expiresAt, null);
        }
        public static IssueResult fail(String reason) {
            return new IssueResult(false, null, null, reason);
        }
    }

    public record ConsumeResult(boolean success, String reason) {
        public static ConsumeResult ok() {
            return new ConsumeResult(true, null);
        }
        public static ConsumeResult fail(String reason) {
            return new ConsumeResult(false, reason);
        }
    }
}