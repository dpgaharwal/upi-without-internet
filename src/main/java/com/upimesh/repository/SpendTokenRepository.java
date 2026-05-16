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

/**
 * {@link SpendToken} entity ke liye Spring Data JPA repository.
 *
 * <p>Spend token lifecycle manage karne ke liye custom queries hain —
 * nonce se lookup, active tokens ki list, aur scheduled expiry.
 */
@Repository
public interface SpendTokenRepository extends JpaRepository<SpendToken, Long> {

    /**
     * Nonce se token dhundho — settlement ke waqt server yahi use karta hai
     * {@link PaymentInstruction} ke andar se nonce nikaalke.
     *
     * @param nonce token ka unique nonce
     * @return token agar mila, warna empty
     */
    Optional<SpendToken> findByNonce(String nonce);

    /**
     * Ek sender ke saare active tokens — total reserved amount calculate karne ke liye
     * naya token issue karne se pehle use hota hai.
     *
     * @param senderVpa sender ka VPA
     * @param status filter karne wali status (usually {@code ACTIVE})
     * @return matching tokens ki list
     */
    List<SpendToken> findBySenderVpaAndStatus(String senderVpa, TokenStatus status);

    /**
     * Expired tokens ko bulk mein {@code EXPIRED} mark karo.
     * Scheduled eviction job regularly yeh call karta hai.
     *
     * @param now current time — is se pehle expire hone wale tokens mark honge
     * @return kitne tokens expire kiye gaye
     */
    @Modifying
    @Transactional
    @Query("UPDATE SpendToken t SET t.status = 'EXPIRED' " +
            "WHERE t.status = 'ACTIVE' AND t.expiresAt < :now")
    int expireTokensBefore(Instant now);
}