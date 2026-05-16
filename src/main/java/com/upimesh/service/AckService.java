package com.upimesh.service;

import com.upimesh.crypto.ReceiverKeyHolder;
import com.upimesh.entity.AckPacket;
import com.upimesh.entity.VirtualDevice;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Problem 6 — Offline Receiver Acknowledgement Service.
 *
 * Three responsibilities:
 *  1. createAck()     — receiver device signs a receipt for a packet it received.
 *  2. verifyAck()     — anyone can verify a signature is authentic.
 *  3. gossipAcks()    — propagate acks back through the mesh (reverse direction).
 *
 * The signing material is: packetId + "|" + receiverVpa + "|" + timestamp
 * Algorithm: SHA256withRSA
 *
 * Why this matters:
 *   Without acks, Shubham sends ₹500 offline → gets zero confirmation until both
 *   go online. With acks, Sarvesh's phone signs a receipt the moment it holds the
 *   packet, and that receipt hops back to Shubham even before anyone reaches a bridge.
 */
@Service
@Slf4j
public class AckService {

    @Autowired private ReceiverKeyHolder keyHolder;
    @Autowired private MeshSimulatorService mesh;

    // Global store: packetId -> list of acks (multiple receivers might ack the same packet)
    private final Map<String, List<AckPacket>> ackStore = new ConcurrentHashMap<>();

    // ── Create ────────────────────────────────────────────────────────────────

    /**
     * Called when a VirtualDevice "receives" a payment packet.
     * Signs an AckPacket with the receiver's private key and stores it locally.
     *
     * In real life: phone B receives packet over BLE, immediately signs an ack
     * with its local private key, stores the ack in its local DB.
     *
     * @param packetId   the MeshPacket ID being acknowledged
     * @param receiverVpa VPA of the acknowledging device
     * @return the signed AckPacket, or null if VPA has no keypair
     */
    public AckPacket createAck(String packetId, String receiverVpa) {
        if (!keyHolder.hasKey(receiverVpa)) {
            log.warn("No keypair for receiver VPA: {} — cannot create ack", receiverVpa);
            return null;
        }

        try {
            long timestamp = System.currentTimeMillis();
            String signingMaterial = packetId + "|" + receiverVpa + "|" + timestamp;

            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyHolder.getPrivateKey(receiverVpa));
            signer.update(signingMaterial.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signer.sign());

            AckPacket ack = new AckPacket(packetId, receiverVpa, signature, timestamp, 5);

            // Store in global ack store
            ackStore.computeIfAbsent(packetId, k -> new ArrayList<>()).add(ack);

            // Place the ack on the receiver's device so gossip can carry it back
            VirtualDevice receiverDevice = findDeviceForVpa(receiverVpa);
            if (receiverDevice != null) {
                receiverDevice.holdAck(ack);
            }

            log.info("ACK created: packet={} receiver={} sig={}...",
                    packetId.substring(0, 8), receiverVpa,
                    signature.substring(0, 16));
            return ack;

        } catch (Exception e) {
            log.error("Failed to create ack for packet {}: {}", packetId, e.getMessage());
            return null;
        }
    }

    // ── Verify ───────────────────────────────────────────────────────────────

    /**
     * Verifies the signature on an AckPacket.
     * Returns true only if the signature is valid for the stated receiverVpa.
     *
     * This is what Shubham's phone does when it receives an ack from Sarvesh:
     * it checks the sig against Sarvesh's known public key.
     */
    public boolean verifyAck(AckPacket ack) {
        if (!keyHolder.hasKey(ack.getReceiverVpa())) {
            log.warn("Cannot verify ack — no public key for VPA: {}", ack.getReceiverVpa());
            return false;
        }
        try {
            String signingMaterial = ack.getPacketId() + "|"
                    + ack.getReceiverVpa() + "|" + ack.getTimestamp();

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(keyHolder.getPublicKey(ack.getReceiverVpa()));
            verifier.update(signingMaterial.getBytes(StandardCharsets.UTF_8));

            boolean valid = verifier.verify(Base64.getDecoder().decode(ack.getSignature()));
            log.info("ACK verify for packet={} receiver={}: {}",
                    ack.getPacketId().substring(0, 8), ack.getReceiverVpa(),
                    valid ? "VALID" : "INVALID");
            return valid;

        } catch (Exception e) {
            log.warn("Ack verification exception: {}", e.getMessage());
            return false;
        }
    }

    // ── Gossip ───────────────────────────────────────────────────────────────

    /**
     * Propagates AckPackets from devices that hold them to all other devices.
     * Mirrors gossipOnce() in MeshSimulatorService but for ack direction (receiver → sender).
     * Decrements ack TTL on each hop.
     */
    public int gossipAcks() {
        int transfers = 0;
        List<VirtualDevice> deviceList = new ArrayList<>(mesh.getDevices());

        for (VirtualDevice src : deviceList) {
            for (AckPacket ack : new ArrayList<>(src.getHeldAcks())) {
                if (ack.getTtl() <= 0) continue;

                for (VirtualDevice dst : deviceList) {
                    if (dst == src) continue;
                    if (dst.holdsAck(ack.getPacketId(), ack.getReceiverVpa())) continue;

                    AckPacket copy = new AckPacket(
                            ack.getPacketId(), ack.getReceiverVpa(),
                            ack.getSignature(), ack.getTimestamp(),
                            ack.getTtl() - 1);
                    dst.holdAck(copy);

                    // Also register in global store if not there yet
                    ackStore.computeIfAbsent(ack.getPacketId(), k -> new ArrayList<>())
                            .stream()
                            .filter(a -> a.getReceiverVpa().equals(ack.getReceiverVpa()))
                            .findFirst()
                            .orElseGet(() -> {
                                ackStore.get(ack.getPacketId()).add(copy);
                                return copy;
                            });

                    transfers++;
                }
            }
        }

        log.info("Ack gossip round: {} ack transfers", transfers);
        return transfers;
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /** Returns all acks for a given packetId (from any receiver). */
    public List<AckPacket> getAcksForPacket(String packetId) {
        return ackStore.getOrDefault(packetId, List.of());
    }

    /** Returns all acks in the store (for dashboard). */
    public Map<String, List<AckPacket>> getAllAcks() {
        return ackStore;
    }

    public void clear() {
        ackStore.clear();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private VirtualDevice findDeviceForVpa(String vpa) {
        // Map VPA to device ID by convention (demo only)
        // e.g. "Sarvesh@demo" -> some device. We pick the first non-bridge offline device
        // In real system: the receiver device IS the phone; this would be local.
        return mesh.getDevices().stream()
                .filter(d -> !d.hasInternet())
                .filter(d -> !d.getDeviceId().equals("phone-shubham"))
                .findFirst()
                .orElse(null);
    }
}