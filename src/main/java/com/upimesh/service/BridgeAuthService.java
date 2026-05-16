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
 * Bridge node registration + HMAC-signed upload verification.
 *
 * HOW IT WORKS:
 *
 * Registration (online, one-time):
 *   Bridge calls POST /api/bridge/register with { nodeId, hmacSecret }.
 *   Server stores nodeId → hmacSecret in DB.
 *   From now on, this bridge is "known".
 *
 * Upload (when bridge has packets to flush):
 *   Bridge signs: HMAC-SHA256(ciphertext, hmacSecret) → base64 signature.
 *   Bridge sends: POST /api/bridge/ingest with:
 *     - X-Bridge-Node-Id: <nodeId>
 *     - X-Bridge-Signature: <base64 HMAC>
 *     - body: MeshPacket JSON
 *   Server calls BridgeAuthService.verifyUpload():
 *     1. Looks up nodeId in DB. If not found → REJECT (unknown bridge).
 *     2. If revoked → REJECT.
 *     3. Recomputes HMAC(ciphertext, stored secret). Compare with header. If mismatch → REJECT.
 *     4. All good → proceed to BridgeIngestionService.
 *
 * WHY HMAC OVER THE CIPHERTEXT:
 *   The ciphertext is already tamper-proof (AES-GCM authenticated encryption).
 *   But without bridge auth, ANY node can POST any ciphertext pretending to be a bridge.
 *   HMAC ties the upload to a specific registered bridge identity.
 *   This enables: per-bridge rate limiting, revocation, audit trail.
 *
 * Revocation:
 *   POST /api/bridge/revoke/{nodeId} sets revoked=true.
 *   All subsequent uploads from that bridge are rejected at the auth layer,
 *   before even touching the ingestion pipeline.
 */
@Service
@Slf4j
public class BridgeAuthService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    @Autowired private BridgeNodeRepository bridgeRepo;

    // ── Registration ─────────────────────────────────────────────────────────

    /**
     * Register a new bridge node.
     * Idempotent — if nodeId already exists, returns existing node (does NOT update secret).
     * In production: this would require admin auth, not an open endpoint.
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

    // ── Verification ─────────────────────────────────────────────────────────

    /**
     * Verify a bridge upload.
     *
     * @param nodeId    value from X-Bridge-Node-Id header
     * @param signature value from X-Bridge-Signature header (base64 HMAC)
     * @param ciphertext the raw ciphertext from the MeshPacket body (what was signed)
     * @return VerifyResult
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

    // ── Revocation ────────────────────────────────────────────────────────────

    public RevokeResult revoke(String nodeId) {
        BridgeNode node = bridgeRepo.findById(nodeId).orElse(null);
        if (node == null) return RevokeResult.fail("unknown_bridge_node");
        if (node.isRevoked()) return RevokeResult.fail("already_revoked");

        node.setRevoked(true);
        bridgeRepo.save(node);
        log.info("Bridge revoked: nodeId={}", nodeId);
        return RevokeResult.ok();
    }

    // ── HMAC utility ─────────────────────────────────────────────────────────

    /**
     * Compute HMAC-SHA256(data, secretBase64) → base64 string.
     * This is what the bridge must do before each upload.
     */
    public String computeHmac(String data, String secretBase64) throws Exception {
        byte[] secretBytes = Base64.getDecoder().decode(secretBase64);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(secretBytes, HMAC_ALGORITHM));
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    // ── List ─────────────────────────────────────────────────────────────────

    public List<BridgeNode> listAll() {
        return bridgeRepo.findAll();
    }

    public List<BridgeNode> listActive() {
        return bridgeRepo.findByRevokedFalse();
    }

    // ── Result records ───────────────────────────────────────────────────────

    public record RegisterResult(boolean success, String reason, BridgeNode node,
                                 boolean alreadyExisted) {
        public static RegisterResult ok(BridgeNode node, boolean existed) {
            return new RegisterResult(true, null, node, existed);
        }
        public static RegisterResult fail(String reason) {
            return new RegisterResult(false, reason, null, false);
        }
    }

    public record VerifyResult(boolean success, String reason) {
        public static VerifyResult ok() { return new VerifyResult(true, null); }
        public static VerifyResult fail(String r) { return new VerifyResult(false, r); }
    }

    public record RevokeResult(boolean success, String reason) {
        public static RevokeResult ok() { return new RevokeResult(true, null); }
        public static RevokeResult fail(String r) { return new RevokeResult(false, r); }
    }
}