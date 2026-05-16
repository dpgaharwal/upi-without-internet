package com.upimesh.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Problem 6 — Offline Receiver Acknowledgement
 *
 * Signed receipt that travels back through the mesh from receiver to sender.
 *
 * Flow:
 *   1. Receiver decrypts nothing (they can't — it's encrypted for server).
 *      But they DO receive the packet and sign an ack proving "I got this".
 *   2. ReceiverKeyHolder holds a per-VPA RSA keypair (generated at demo startup).
 *   3. AckService.createAck() signs (packetId + receiverVpa + timestamp) with
 *      the receiver's private key and stores it on the receiver's VirtualDevice.
 *   4. Gossip propagates AckPackets back toward the sender device.
 *   5. Any device can verify the ack via POST /api/mesh/ack/gossip.
 *   6. GET /api/acks/{packetId} returns all known acks — sender checks these.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AckPacket {

    /** The original MeshPacket ID being acknowledged. */
    private String packetId;

    /** VPA of the device that received the payment packet. */
    private String receiverVpa;

    /**
     * RSA-SHA256 signature over: packetId + "|" + receiverVpa + "|" + timestamp
     * Base64-encoded. Verified using ReceiverKeyHolder's public key for receiverVpa.
     */
    private String signature;

    /** Epoch millis when the ack was created. */
    private long timestamp;

    /** How many more hops this ack can travel (starts at 5, decremented on each hop). */
    private int ttl;
}
