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
 * Offline receiver acknowledgement manage karta hai.
 *
 * <p>Teen kaam karta hai:
 * <ol>
 *   <li>{@link #createAck} — receiver device packet receive karne par signed receipt banata hai.</li>
 *   <li>{@link #verifyAck} — koi bhi signature authentic hai ya nahi check kar sakta hai.</li>
 *   <li>{@link #gossipAcks} — acks mesh mein ulti direction mein propagate karta hai
 *       (receiver se sender ki taraf).</li>
 * </ol>
 *
 * <p>Signing material: {@code packetId + "|" + receiverVpa + "|" + timestamp}
 * Algorithm: {@code SHA256withRSA}
 *
 * <p>Bina ack ke sender ko tab tak koi confirmation nahi milta jab tak dono online na aa jayein.
 * Ack ke saath receiver ka device packet milte hi receipt sign karta hai aur woh gossip se sender
 * tak pahunch jaata hai — settlement se pehle bhi.
 */
@Service
@Slf4j
public class AckService {

    @Autowired private ReceiverKeyHolder keyHolder;
    @Autowired private MeshSimulatorService mesh;

    /** Global store: packetId → acks ki list (multiple receivers ack kar sakte hain). */
    private final Map<String, List<AckPacket>> ackStore = new ConcurrentHashMap<>();

    /**
     * Payment packet receive karne par receiver device se signed ack banao.
     *
     * <p>Real life mein: phone B BLE se packet receive karta hai, turant apni local
     * private key se ack sign karta hai aur local DB mein store karta hai.
     *
     * @param packetId    acknowledge karne wale packet ka ID
     * @param receiverVpa ack karne wale device ka VPA
     * @return signed {@link AckPacket}, ya {@code null} agar VPA ka keypair nahi hai
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

    /**
     * AckPacket ka signature verify karo.
     * Sirf tab {@code true} return hoga jab signature stated {@code receiverVpa} ke
     * liye valid ho — receiver ki public key se check hota hai.
     *
     * @param ack verify karne wala ack packet
     * @return {@code true} agar signature valid hai
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

    /**
     * Acks ko mesh mein propagate karo — receiver se sender ki taraf (ulti direction).
     * {@link MeshSimulatorService#gossipOnce()} jaisa hai lekin ack packets ke liye.
     * Har hop pe ack TTL ek se kam hota hai.
     *
     * @return kitne ack transfers hue is gossip round mein
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

    /**
     * Ek packet ke saare acks return karo (kisi bhi receiver se).
     * Sender yeh call karke confirm karta hai ki payment kisi ne receive ki.
     *
     * @param packetId jis packet ke acks chahiye
     * @return ack packets ki list, empty agar koi nahi mila
     */
    public List<AckPacket> getAcksForPacket(String packetId) {
        return ackStore.getOrDefault(packetId, List.of());
    }

    /**
     * Store ke saare acks return karo — dashboard display ke liye.
     *
     * @return packetId to ack list ka map
     */
    public Map<String, List<AckPacket>> getAllAcks() {
        return ackStore;
    }

    /** Ack store completely clear karo — mesh reset ke waqt use hota hai. */
    public void clear() {
        ackStore.clear();
    }

    /**
     * VPA ke hisaab se receiver ka virtual device dhundho.
     * Demo convention: pehla non-bridge offline device use hota hai.
     * Real system mein: receiver device khud hi local hota, yeh lookup nahi lagta.
     *
     * @param vpa receiver ka VPA
     * @return matching {@link VirtualDevice}, ya {@code null} agar nahi mila
     */
    private VirtualDevice findDeviceForVpa(String vpa) {
                .filter(d -> !d.hasInternet())
                .filter(d -> !d.getDeviceId().equals("phone-shubham"))
                .findFirst()
                .orElse(null);
    }
}