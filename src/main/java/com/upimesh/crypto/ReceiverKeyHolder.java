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
 * Problem 6 — Per-receiver RSA keypair store.
 *
 * In a real app each phone generates its own keypair locally (never leaves device).
 * Here we simulate it server-side: one keypair per demo VPA, generated at startup.
 *
 * Why RSA per VPA and not reuse ServerKeyHolder?
 * ServerKeyHolder is the SERVER's key. Receiver acks must be signed by the RECEIVER
 * so the sender can verify "this person specifically acknowledged my payment".
 * Using the server key would only prove the server created the ack, not the receiver.
 */
@Component
@Slf4j
public class ReceiverKeyHolder {

    // vpa -> keypair
    private final Map<String, KeyPair> keyPairs = new ConcurrentHashMap<>();

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
     * Register a new VPA dynamically (e.g. if a new demo account is added).
     * Idempotent — if VPA already has a keypair, does nothing.
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

    public PrivateKey getPrivateKey(String vpa) {
        KeyPair kp = keyPairs.get(vpa);
        if (kp == null) throw new IllegalArgumentException("No keypair for VPA: " + vpa);
        return kp.getPrivate();
    }

    public PublicKey getPublicKey(String vpa) {
        KeyPair kp = keyPairs.get(vpa);
        if (kp == null) throw new IllegalArgumentException("No keypair for VPA: " + vpa);
        return kp.getPublic();
    }

    public boolean hasKey(String vpa) {
        return keyPairs.containsKey(vpa);
    }
}