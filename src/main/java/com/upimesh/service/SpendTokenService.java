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
 * Offline spend tokens manage karta hai — double-spend prevention ka core.
 *
 * <p>Bina token ke, ek sender offline hoke ek hi balance se do alag payments sign
 * kar sakta hai. Dono packets valid dikhenge. Jo bridge pehle upload karega woh settle
 * hoga, doosra REJECTED hoga — lekin doosra receiver confused rahega.
 *
 * <p>Token ke saath, server issuance pe hi check karta hai ki
 * {@code balance - already_reserved >= requestedAmount}. Same balance pe doosra token
 * issuance fail hoga {@code INSUFFICIENT_BALANCE_FOR_RESERVATION} se — packet hi
 * nahi banega.
 *
 * <p>Consume contract (exactly-once):
 * {@link #consume} {@code @Transactional} mein chalta hai aur select-then-update karta hai.
 * {@code nonce} pe unique index aur {@code status=ACTIVE} guard ensure karta hai ki sirf
 * ek thread win kare — doosra ya to {@code CONSUMED} status dekhega ya constraint violation.
 *
 * <p>Token lifecycle:
 * <pre>
 *   ACTIVE --[settle]--> CONSUMED
 *   ACTIVE --[expiry]--> EXPIRED
 * </pre>
 */
@Service
@Slf4j
public class SpendTokenService {

    @Autowired private SpendTokenRepository tokenRepo;
    @Autowired private AccountRepository accountRepo;

    @Value("${upi.mesh.token-ttl-seconds:86400}")
    private long tokenTtlSeconds;

    /**
     * Sender ke liye ek spend token issue karo jo exactly {@code amount} authorize kare.
     *
     * <p>Do checks:
     * <ol>
     *   <li>Sender exist karna chahiye.</li>
     *   <li>{@code balance - totalActiveReserved >= amount} hona chahiye.</li>
     * </ol>
     *
     * <p>Token ka nonce sender ke phone ko milta hai jo ise {@link com.upimesh.entity.PaymentInstruction}
     * mein encrypt karke embed karta hai. Nonce kabhi cleartext mein travel nahi karta.
     *
     * @param senderVpa jis sender ke liye token chahiye
     * @param amount    kitna amount reserve karna hai
     * @return {@link IssueResult} — success mein nonce aur expiry, fail mein reason
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

    /**
     * Settlement ke waqt spend token consume karo.
     *
     * <p>Yeh checks hote hain:
     * <ul>
     *   <li>Token nonce exist karna chahiye.</li>
     *   <li>Token {@code ACTIVE} hona chahiye — {@code CONSUMED} ya {@code EXPIRED} nahi.</li>
     *   <li>Token ka {@code senderVpa} payment ke {@code senderVpa} se match karna chahiye.</li>
     *   <li>Token ka {@code reservedAmount} exactly payment amount ke barabar hona chahiye.</li>
     *   <li>Token abhi expire nahi hua hona chahiye.</li>
     * </ul>
     *
     * <p>Sab checks pass hone par token {@code CONSUMED} mark hota hai. Koi bhi fail
     * hone par {@code false} return hota hai aur settlement reject hoti hai.
     *
     * @param nonce       {@link com.upimesh.entity.PaymentInstruction} mein embedded token nonce
     * @param senderVpa   payment ka sender VPA — token VPA se match hona chahiye
     * @param amount      payment amount — token reserved amount se exactly match hona chahiye
     * @param packetHash  audit trail ke liye
     * @return {@link ConsumeResult} — success ya reason ke saath failure
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

    /**
     * Nonce se token ki current state fetch karo — dashboard ke liye.
     *
     * @param nonce token ka nonce
     * @return {@link SpendToken} agar mila, warna {@code null}
     */
    public SpendToken getByNonce(String nonce) {
        return tokenRepo.findByNonce(nonce).orElse(null);
    }

    /**
     * Ek sender ke saare active tokens return karo — dashboard display ke liye.
     *
     * @param senderVpa sender ka VPA
     * @return active tokens ki list
     */
    public List<SpendToken> getTokensForSender(String senderVpa) {
        return tokenRepo.findBySenderVpaAndStatus(senderVpa, TokenStatus.ACTIVE);
    }

    /**
     * Har 60 seconds mein chalta hai. Time limit khatam hone wale tokens bulk mein
     * {@code EXPIRED} mark karta hai taaki DB clean rahe.
     */
    @Scheduled(fixedDelay = 60_000)
    @Transactional
    public void evictExpiredTokens() {
        int count = tokenRepo.expireTokensBefore(Instant.now());
        if (count > 0) {
            log.info("Evicted {} expired spend token(s)", count);
        }
    }

    /**
     * Token issuance ka result.
     *
     * @param success   {@code true} agar token issue hua
     * @param nonce     issued token ka nonce (sirf success mein)
     * @param expiresAt kab token expire hoga (sirf success mein)
     * @param reason    failure ka reason (sirf fail mein)
     */
    public record IssueResult(boolean success, String nonce, Instant expiresAt, String reason) {
        public static IssueResult ok(String nonce, Instant expiresAt) {
            return new IssueResult(true, nonce, expiresAt, null);
        }
        public static IssueResult fail(String reason) {
            return new IssueResult(false, null, null, reason);
        }
    }

    /**
     * Token consume karne ka result.
     *
     * @param success {@code true} agar token successfully consume hua
     * @param reason  failure ka reason (sirf fail mein)
     */
    public record ConsumeResult(boolean success, String reason) {
        public static ConsumeResult ok() {
            return new ConsumeResult(true, null);
        }
        public static ConsumeResult fail(String reason) {
            return new ConsumeResult(false, reason);
        }
    }
}