package com.upimesh.service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * In-memory idempotency cache — exactly-once settlement ensure karta hai.
 *
 * <p>Contract:
 * <ul>
 *   <li>{@link #claim(String)} pehli baar {@code true} return karta hai, baad mein
 *       {@code false} (TTL window ke andar).</li>
 *   <li>Operation atomic hai — 100 threads ek saath {@code claim(hash)} call karein
 *       to exactly ek {@code true} paayega. {@code ConcurrentHashMap.putIfAbsent}
 *       JVM-local equivalent hai Redis {@code SETNX} ka.</li>
 * </ul>
 *
 * <p>Production mein yeh Redis Cluster hoga {@code SET key NX EX ttl} ke saath —
 * bilkul same semantics, distributed across instances. Yahan in-memory kyunki
 * single JVM demo hai.
 */
@Service
public class IdempotencyService {

  private final Map<String, Instant> seen = new ConcurrentHashMap<>();

  @Value("${upi.mesh.idempotency-ttl-seconds:86400}")
  private long ttlSeconds;

  /**
   * Hash claim karo. Pehla caller {@code true} paata hai, baaki sab {@code false}.
   * Duplicate packet ko yahan hi rok diya jaata hai — bina decrypt kiye.
   *
   * @param packetHash SHA-256 hex of ciphertext
   * @return {@code true} agar pehli baar claim hua, {@code false} agar duplicate hai
   */
  public boolean claim(String packetHash) {
    Instant now = Instant.now();
    Instant prev = seen.putIfAbsent(packetHash, now);
    return prev == null;
  }

  /** Cache mein kitne entries hain — monitoring ke liye. */
  public int size() {
    return seen.size();
  }

  /** TTL expire ho chuke entries ko periodically hata do taaki map zyada bada na ho. */
  @Scheduled(fixedDelay = 60000)
  public void evictExpired() {
    Instant cutoff = Instant.now().minusSeconds(ttlSeconds);
    seen.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
  }

  /** Cache completely clear karo — mesh reset ke waqt use hota hai. */
  public void clear() {
    seen.clear();
  }
}
