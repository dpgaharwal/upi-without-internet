package com.upimesh.crypto;

import jakarta.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Har demo VPA ke liye RSA keypair store karta hai — receiver acknowledgement ke liye.
 *
 * <p>Real app mein har phone apna keypair locally generate karta (device se kabhi nahi
 * nikalta). Yahan demo ke liye server-side simulate kiya gaya hai — ek keypair per VPA,
 * startup pe generate hote hain.
 *
 * <p>{@link com.upimesh.crypto.ServerKeyHolder} server ka key hai — woh aise nahi use
 * kar sakte kyunki receiver ka ack receiver ne sign kiya hona chahiye, server ne nahi.
 * Sirf receiver ka private key se sign kiya hua ack prove karta hai ki usi specific
 * receiver ne payment receive ki.
 */
@Component
@Slf4j
public class ReceiverKeyHolder {

    // vpa -> keypair
    private final Map<String, KeyPair> keyPairs = new ConcurrentHashMap<>();

    /**
     * Startup pe demo VPAs ke liye RSA-2048 keypairs generate karo.
     * Real system mein: har phone install pe generate karta, server sirf public key store karta.
     *
     * @throws Exception agar key generation fail ho
     */
    @PostConstruct
    public void init() throws Exception {
        // Seed keypairs for all demo VPAs
        // In real system: each phone generates on install, server stores only the public key
        for (String vpa : new String[]{
                "ShubhamTiwari@demo", "Sarvesh@demo", "Rushabh@demo", "Sudarshan@demo"}) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            keyPairs.put(vpa, gen.generateKeyPair());
            log.info("RSA keypair generated for receiver VPA: {}", vpa);
        }
    }

    /**
     * Nayi VPA ke liye keypair register karo agar already nahi hai.
     * Idempotent — existing VPA ka keypair overwrite nahi hoga.
     *
     * @param vpa jis VPA ke liye keypair chahiye
     */
    public void registerIfAbsent(String vpa) {
        keyPairs.computeIfAbsent(vpa, v -> {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                return gen.generateKeyPair();
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate keypair for " + v, e);
            }
        });
    }

    /**
     * Ack sign karne ke liye receiver ki private key do.
     *
     * @param vpa receiver ka VPA
     * @return RSA private key
     * @throws IllegalArgumentException agar VPA registered nahi hai
     */
    public PrivateKey getPrivateKey(String vpa) {
        KeyPair kp = keyPairs.get(vpa);
        if (kp == null) throw new IllegalArgumentException("No keypair for VPA: " + vpa);
        return kp.getPrivate();
    }

    /**
     * Ack verify karne ke liye receiver ki public key do.
     *
     * @param vpa receiver ka VPA
     * @return RSA public key
     * @throws IllegalArgumentException agar VPA registered nahi hai
     */
    public PublicKey getPublicKey(String vpa) {
        KeyPair kp = keyPairs.get(vpa);
        if (kp == null) throw new IllegalArgumentException("No keypair for VPA: " + vpa);
        return kp.getPublic();
    }

    /**
     * Check karo ki is VPA ke liye keypair registered hai ya nahi.
     *
     * @param vpa check karne wala VPA
     * @return {@code true} agar keypair exist karta hai
     */
    public boolean hasKey(String vpa) {
        return keyPairs.containsKey(vpa);
    }
}