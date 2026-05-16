package com.upimesh.service;

import com.upimesh.entity.BridgeNode;
import com.upimesh.repository.BridgeNodeRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * Bridge node registration aur HMAC-signed upload verification manage karta hai.
 *
 * <p>Registration (ek baar, online mein):
 * Bridge {@code POST /api/bridge/register} call karta hai {@code { nodeId, hmacSecret }} ke saath.
 * Server {@code nodeId → hmacSecret} DB mein store karta hai. Ab yeh bridge "known" hai.
 *
 * <p>Upload (jab bridge packets flush karna chahta hai):
 * Bridge {@code HMAC-SHA256(ciphertext, hmacSecret)} compute karta hai aur
 * {@code X-Bridge-Signature} header mein bhejta hai. Server {@link #verifyUpload} call karta hai:
 * <ol>
 *   <li>NodeId DB mein dhundho — nahi mila to reject.</li>
 *   <li>Revoked hai to reject.</li>
 *   <li>HMAC recompute karo aur header se compare karo — mismatch to reject.</li>
 *   <li>Sab theek to ingestion pipeline mein jaane do.</li>
 * </ol>
 *
 * <p>Ciphertext pe HMAC kyun: ciphertext already AES-GCM se tamper-proof hai, lekin
 * bridge auth ke bina koi bhi node koi bhi ciphertext POST kar sakta tha. HMAC upload
 * ko ek specific registered bridge identity se tie karta hai — per-bridge rate limiting
 * aur revocation enable hota hai.
 */
@Service
@Slf4j
public class BridgeAuthService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    @Autowired private BridgeNodeRepository bridgeRepo;

    /**
     * Nayi bridge node register karo.
     * Idempotent — agar nodeId already exist karta hai to existing node return hota hai
     * (secret update nahi hota). Production mein yeh admin auth ke peeche hona chahiye.
     *
     * @param nodeId          bridge ka unique identifier
     * @param hmacSecretBase64 base64-encoded HMAC secret, minimum 32 bytes
     * @return {@link RegisterResult} — success ya failure reason ke saath
     */
    public RegisterResult register(String nodeId, String hmacSecretBase64) {
        if (nodeId == null || nodeId.isBlank()) {
            return RegisterResult.fail("nodeId_required");
        }
        if (hmacSecretBase64 == null || hmacSecretBase64.isBlank()) {
            return RegisterResult.fail("hmacSecret_required");
        }

        // Validate the secret is valid base64 and at least 32 bytes (256-bit minimum)
        try {
            byte[] secretBytes = Base64.getDecoder().decode(hmacSecretBase64);
            if (secretBytes.length < 32) {
                return RegisterResult.fail("hmacSecret_too_short_min_32_bytes");
            }
        } catch (IllegalArgumentException e) {
            return RegisterResult.fail("hmacSecret_must_be_base64");
        }

        if (bridgeRepo.existsById(nodeId)) {
            BridgeNode existing = bridgeRepo.findById(nodeId).get();
            if (existing.isRevoked()) {
                return RegisterResult.fail("nodeId_is_revoked");
            }
            log.info("Bridge re-registration attempt for existing nodeId: {}", nodeId);
            return RegisterResult.ok(existing, true);
        }

        BridgeNode node = new BridgeNode(nodeId, hmacSecretBase64, Instant.now());
        bridgeRepo.save(node);
        log.info("Bridge registered: nodeId={}", nodeId);
        return RegisterResult.ok(node, false);
    }

    /**
     * Bridge upload verify karo — nodeId check, revocation check, HMAC signature verify.
     *
     * @param nodeId     {@code X-Bridge-Node-Id} header ki value
     * @param signature  {@code X-Bridge-Signature} header ki value (base64 HMAC)
     * @param ciphertext {@link com.upimesh.entity.MeshPacket} body ka ciphertext (jo sign hua tha)
     * @return {@link VerifyResult} — success ya failure reason ke saath
     */
    public VerifyResult verifyUpload(String nodeId, String signature, String ciphertext) {
        if (nodeId == null || nodeId.isBlank() || nodeId.equals("unknown")) {
            log.warn("Bridge upload rejected: missing nodeId");
            return VerifyResult.fail("missing_node_id");
        }
        if (signature == null || signature.isBlank()) {
            log.warn("Bridge upload rejected: missing signature from node {}", nodeId);
            return VerifyResult.fail("missing_signature");
        }

        BridgeNode node = bridgeRepo.findById(nodeId).orElse(null);
        if (node == null) {
            log.warn("Bridge upload rejected: unknown nodeId={}", nodeId);
            return VerifyResult.fail("unknown_bridge_node");
        }
        if (node.isRevoked()) {
            log.warn("Bridge upload rejected: revoked nodeId={}", nodeId);
            return VerifyResult.fail("bridge_node_revoked");
        }

        // Recompute HMAC and compare
        try {
            String expectedSig = computeHmac(ciphertext, node.getHmacSecret());
            if (!expectedSig.equals(signature)) {
                log.warn("Bridge upload rejected: signature mismatch from node={}", nodeId);
                return VerifyResult.fail("signature_mismatch");
            }
        } catch (Exception e) {
            log.error("HMAC verification error for node {}: {}", nodeId, e.getMessage());
            return VerifyResult.fail("hmac_error");
        }

        log.info("Bridge upload verified: nodeId={}", nodeId);
        return VerifyResult.ok();
    }

    /**
     * Bridge node revoke karo — iske baad is bridge ke saare uploads reject honge.
     *
     * @param nodeId revoke karne wala bridge ID
     * @return {@link RevokeResult} — success ya failure reason
     */
    public RevokeResult revoke(String nodeId) {
        BridgeNode node = bridgeRepo.findById(nodeId).orElse(null);
        if (node == null) return RevokeResult.fail("unknown_bridge_node");
        if (node.isRevoked()) return RevokeResult.fail("already_revoked");

        node.setRevoked(true);
        bridgeRepo.save(node);
        log.info("Bridge revoked: nodeId={}", nodeId);
        return RevokeResult.ok();
    }

    /**
     * {@code HMAC-SHA256(data, secretBase64)} compute karo aur base64 string return karo.
     * Bridge har upload se pehle yahi karta hai; server verify karne ke liye yahi call karta hai.
     *
     * @param data          sign karne wala data (ciphertext)
     * @param secretBase64  base64-encoded HMAC secret
     * @return base64-encoded HMAC signature
     * @throws Exception agar crypto operation fail ho
     */
    public String computeHmac(String data, String secretBase64) throws Exception {
        byte[] secretBytes = Base64.getDecoder().decode(secretBase64);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(secretBytes, HMAC_ALGORITHM));
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    /** Saare registered bridges return karo — active aur revoked dono. Dashboard ke liye. */
    public List<BridgeNode> listAll() {
        return bridgeRepo.findAll();
    }

    /** Sirf active (non-revoked) bridges return karo. */
    public List<BridgeNode> listActive() {
        return bridgeRepo.findByRevokedFalse();
    }

    /**
     * Bridge registration ka result.
     *
     * @param success       {@code true} agar registration successful rahi
     * @param reason        failure ka reason (sirf fail mein)
     * @param node          registered bridge node (sirf success mein)
     * @param alreadyExisted {@code true} agar bridge pehle se registered tha
     */
    public record RegisterResult(boolean success, String reason, BridgeNode node,
                                 boolean alreadyExisted) {
        public static RegisterResult ok(BridgeNode node, boolean existed) {
            return new RegisterResult(true, null, node, existed);
        }
        public static RegisterResult fail(String reason) {
            return new RegisterResult(false, reason, null, false);
        }
    }

    /**
     * Upload verification ka result.
     *
     * @param success {@code true} agar signature valid aur bridge known + active hai
     * @param reason  failure ka reason (sirf fail mein)
     */
    public record VerifyResult(boolean success, String reason) {
        public static VerifyResult ok() { return new VerifyResult(true, null); }
        public static VerifyResult fail(String r) { return new VerifyResult(false, r); }
    }

    /**
     * Bridge revocation ka result.
     *
     * @param success {@code true} agar revocation successful rahi
     * @param reason  failure ka reason (sirf fail mein)
     */
    public record RevokeResult(boolean success, String reason) {
        public static RevokeResult ok() { return new RevokeResult(true, null); }
        public static RevokeResult fail(String r) { return new RevokeResult(false, r); }
    }
}