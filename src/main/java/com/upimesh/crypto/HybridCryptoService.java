package com.upimesh.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upimesh.entity.PaymentInstruction;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Hybrid encryption — TLS, PGP, Signal jaisi wahi pattern.
 *
 * <p>RSA kyun nahi akela? RSA-2048 sirf ~245 bytes plaintext encrypt kar sakta hai.
 * Payment instruction JSON pehle hi ~300 bytes hoti hai — RSA akela fail ho jaata.
 *
 * <p>Solution — hybrid approach:
 * <ol>
 *   <li>Har packet ke liye ek fresh random AES-256 key generate karo.</li>
 *   <li>Payment instruction JSON ko AES-GCM se encrypt karo (fast + authenticated).</li>
 *   <li>Sirf AES key ko RSA-OAEP se encrypt karo (yeh small enough hai RSA ke liye).</li>
 * </ol>
 *
 * <p>Wire format (base64-encoded):
 * {@code [256 bytes RSA-encrypted AES key][12 bytes GCM IV][ciphertext + 16-byte GCM tag]}
 *
 * <p>AES-GCM authenticated encryption hai: ciphertext mein ek bhi bit badalne par
 * decryption exception throw karta hai. Isliye untrusted intermediate devices safely
 * packet hold kar sakte hain — tamper impossible hai.
 */
@Service
public class HybridCryptoService {

  private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
  private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int AES_KEY_BITS = 256;
  private static final int GCM_IV_BYTES = 12;
  private static final int GCM_TAG_BITS = 128;
  private static final int RSA_ENCRYPTED_KEY_BYTES = 256; // 2048-bit RSA ke liye

  private final SecureRandom rng = new SecureRandom();
  private final ObjectMapper json = new ObjectMapper();

  @Autowired private ServerKeyHolder serverKey;

  /**
   * Payment instruction ko server ki public key se encrypt karo.
   * Simulated sender device yeh call karta hai packet banate waqt.
   *
   * @param instruction encrypt karne wali payment details
   * @param serverPublicKey server ki RSA-2048 public key
   * @return base64-encoded hybrid ciphertext
   * @throws Exception agar encryption fail ho
   */
  public String encrypt(PaymentInstruction instruction, PublicKey serverPublicKey)
      throws Exception {
    byte[] plaintext = json.writeValueAsBytes(instruction);

    // 1. Generate a 1-time AES key for this packet.
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(AES_KEY_BITS);
    SecretKey aesKey = kg.generateKey();

    // 2. Payload encrypt by AES-GCM
    byte[] iv = new byte[GCM_IV_BYTES];
    rng.nextBytes(iv);
    Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
    byte[] aesCiphertext = cipher.doFinal(plaintext);

    // 3. RSA-OAEP encrypt the AES key with the server's public key.
    Cipher rsa = Cipher.getInstance(RSA_TRANSFORMATION);
    OAEPParameterSpec oaep =
        new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT);
    rsa.init(Cipher.ENCRYPT_MODE, serverPublicKey, oaep);
    byte[] encyptedAesKey = rsa.doFinal(aesKey.getEncoded());

    // 4. Pack: [encrypted AES key][IV][AES ciphertext + tag]
    ByteBuffer buf = ByteBuffer.allocate(encyptedAesKey.length + iv.length + aesCiphertext.length);
    buf.put(encyptedAesKey);
    buf.put(iv);
    buf.put(aesCiphertext);

    return Base64.getEncoder().encodeToString(buf.array());
  }

  /**
   * Server ki private key se decrypt karo.
   * Kuch bhi tamper hua ho — wrong key, modified ciphertext, truncated input — yeh throw karta hai.
   *
   * @param base64Ciphertext base64-encoded hybrid ciphertext
   * @return decrypted {@link PaymentInstruction}
   * @throws Exception agar decryption ya deserialization fail ho (tamper detected)
   */
  public PaymentInstruction decrypt(String base64Ciphertext) throws Exception {

    // decode first ciphertext (string to byte)
    byte[] all = Base64.getDecoder().decode(base64Ciphertext);

    // Sanity Check
    if (all.length < RSA_ENCRYPTED_KEY_BYTES + GCM_IV_BYTES + GCM_TAG_BITS / 8) {
      throw new IllegalArgumentException("Ciphertext is too short");
    }

    // Unpack
    byte[] encryptedAesKey = new byte[RSA_ENCRYPTED_KEY_BYTES];
    byte[] iv = new byte[GCM_IV_BYTES];
    byte[] aesCiphertext = new byte[all.length - RSA_ENCRYPTED_KEY_BYTES - GCM_IV_BYTES];

    ByteBuffer buf = ByteBuffer.wrap(all);
    buf.get(encryptedAesKey);
    buf.get(iv);
    buf.get(aesCiphertext);

    // 1. RSA-decrypt se aes key nikalo
    Cipher rsa = Cipher.getInstance(RSA_TRANSFORMATION);
    OAEPParameterSpec oaep =
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    rsa.init(Cipher.DECRYPT_MODE, serverKey.getPrivateKey(), oaep);
    byte[] aesKeyBytes = rsa.doFinal(encryptedAesKey);
    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

    // aes-gcm decrypt --> payment nikalo
    Cipher aes = Cipher.getInstance(AES_TRANSFORMATION);
    aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
    byte[] plaintext = aes.doFinal(aesCiphertext);

    // bytes --> payment instruction
    return json.readValue(plaintext, PaymentInstruction.class);
  }

  /**
   * Ciphertext ka SHA-256 hash — yahi idempotency key hai.
   *
   * <p>{@code packetId} outer cleartext mein hai aur koi bhi intermediate rewrite kar sakta hai.
   * Ciphertext immutable hai — koi bhi change GCM tag fail karata hai. Isliye
   * {@code SHA-256(ciphertext)} tamper-proof dedup key hai. Do duplicate deliveries ka
   * ciphertext byte-identical hota hai, hence hash identical.
   *
   * @param base64Ciphertext base64-encoded ciphertext
   * @return lowercase hex SHA-256 digest
   * @throws Exception agar hashing fail ho
   */
  public String hashCiphertext(String base64Ciphertext) throws Exception {
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] hash = sha256.digest(base64Ciphertext.getBytes());
    StringBuilder hex = new StringBuilder();
    for (byte b : hash) {
      hex.append(String.format("%02x", b));
    }
    return hex.toString();
  }
}
