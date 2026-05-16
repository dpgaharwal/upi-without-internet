package com.upimesh.crypto;

import jakarta.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Server ka RSA-2048 keypair hold karta hai.
 *
 * <p>Public key {@code /api/server-key} endpoint se milti hai — simulated sender
 * devices ise download karke payment encrypt karte hain. Private key sirf server
 * ke paas rahti hai aur decrypt karne ke liye use hoti hai.
 *
 * <p>Production mein private key kabhi JAR ya source mein nahi honi chahiye —
 * AWS KMS, HashiCorp Vault, ya HSM mein rakho. Demo mein har startup pe fresh
 * keypair generate hota hai jo H2 database ki tarah in-memory rehta hai.
 */
@Component
@Slf4j
public class ServerKeyHolder {
  //  private static final Logger log = LoggerFactory.getLogger(ServerKeyHolder.class);

  private KeyPair keyPair;

  /**
   * Startup pe RSA-2048 keypair generate karo.
   * Public key fingerprint log mein print hoti hai confirmation ke liye.
   *
   * @throws Exception agar JVM mein RSA algorithm available nahi hai
   */
  @PostConstruct
  public void init() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    this.keyPair = gen.generateKeyPair();
    log.info(
        "Server RSA keypair generated (2048-bit). Public key fingerprint: {}",
        getPublicKeyBase64().substring(0, 32) + "...");
  }

  /** Server ki RSA public key — sender devices ise encrypt karne ke liye use karte hain. */
  public PublicKey getPublicKey() {
    return keyPair.getPublic();
  }

  /** Server ki RSA private key — sirf server decrypt karne ke liye use karta hai. */
  public PrivateKey getPrivateKey() {
    return keyPair.getPrivate();
  }

  /** Public key base64 format mein — {@code /api/server-key} endpoint return karta hai yeh. */
  public String getPublicKeyBase64() {
    return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
  }
}
