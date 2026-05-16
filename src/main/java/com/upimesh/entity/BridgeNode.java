package com.upimesh.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Bridge node identity.
 *
 * Each bridge that wants to call /api/bridge/ingest must first register via
 * POST /api/bridge/register. The server stores its publicKey.
 *
 * On every upload, the bridge HMAC-SHA256 signs the packet ciphertext with its
 * secret key (derived from its keypair or a shared secret set at registration).
 * The server verifies using the stored publicKey. If signature is wrong or the
 * nodeId is revoked, the upload is rejected.
 *
 * Fields:
 *   nodeId       — the X-Bridge-Node-Id header value. Chosen by the bridge at registration.
 *   publicKey    — base64-encoded RSA public key (or HMAC shared secret, base64).
 *                  We use HMAC-SHA256 with a shared secret for simplicity:
 *                  registration sends the secret, server stores it, bridge uses it to sign.
 *   registeredAt — when it registered.
 *   revoked      — if true, all uploads from this nodeId are rejected with 403.
 */
@Entity
@Table(name = "bridge_nodes")
@Getter
@Setter
@NoArgsConstructor
public class BridgeNode {

    @Id
    @Column(nullable = false, length = 128)
    private String nodeId;

    /**
     * HMAC-SHA256 shared secret, base64-encoded.
     * Bridge knows this secret; uses it to sign each upload.
     * Server stores it to verify.
     *
     * In production: use asymmetric keys (bridge holds private, server holds public).
     * HMAC is simpler for this demo and equally tamper-proof.
     */
    @Column(nullable = false, length = 512)
    private String hmacSecret;

    @Column(nullable = false)
    private Instant registeredAt;

    /** When true, all uploads from this node are rejected. Enables per-bridge revocation. */
    @Column(nullable = false)
    private boolean revoked = false;

    public BridgeNode(String nodeId, String hmacSecret, Instant registeredAt) {
        this.nodeId = nodeId;
        this.hmacSecret = hmacSecret;
        this.registeredAt = registeredAt;
        this.revoked = false;
    }
}