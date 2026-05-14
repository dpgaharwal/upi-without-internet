package com.upimesh.repository;

import com.upimesh.entity.SpendToken;
import com.upimesh.enums.TokenStatus;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface SpendTokenRepository extends JpaRepository<SpendToken, Long> {

    /** Look up a token by its nonce — the value embedded in the PaymentInstruction. */
    Optional<SpendToken> findByNonce(String nonce);

    /** All active tokens for a sender — used to compute total reserved amount. */
    List<SpendToken> findBySenderVpaAndStatus(String senderVpa, TokenStatus status);

    /**
     * Bulk-expire tokens whose expiresAt has passed.
     * Called by the scheduled eviction job in SpendTokenService.
     */
    @Modifying
    @Transactional
    @Query("UPDATE SpendToken t SET t.status = 'EXPIRED' " +
            "WHERE t.status = 'ACTIVE' AND t.expiresAt < :now")
    int expireTokensBefore(Instant now);
}