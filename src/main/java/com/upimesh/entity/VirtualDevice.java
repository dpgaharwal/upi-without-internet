package com.upimesh.entity;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * Mesh mein ek simulated phone device.
 *
 * <p>Real system mein yeh state ek physical Android device pe hoti aur packets
 * BLE GATT characteristics ke zariye exchange hote. Yahan sab kuch in-memory
 * hai demo ke liye.
 *
 * <p>Ek device ya to internet-connected (bridge) hota hai ya offline intermediary.
 * Bridge devices wahi hain jo packets server tak upload karte hain.
 */
@AllArgsConstructor
@Getter
@Setter
public class VirtualDevice {

  /** Is device ka unique identifier, jaise {@code phone-shubham} ya {@code phone-bridge}. */
  private final String deviceId;

  /** {@code true} matlab yeh device 4G/WiFi pe hai aur packets server ko upload kar sakta hai. */
  private final boolean hasInternet;

  /**
   * Device ke paas jo packets hain — key {@code packetId} hai.
   * {@code ConcurrentHashMap} isliye ki gossip multi-threaded ho sakta hai.
   */
  private final Map<String, MeshPacket> heldPackets = new ConcurrentHashMap<>();

  /**
   * Device ke paas jo ack packets hain — key {@code packetId|receiverVpa} hai.
   * Ek device multiple receivers ke acks hold kar sakta hai.
   */
  private final Map<String, AckPacket> heldAcks = new ConcurrentHashMap<>();

  /**
   * Ek packet hold karo. Idempotent — same packet dobara nahi add hoga.
   *
   * @param packet jo packet store karna hai
   */
  public void hold(MeshPacket packet) {
    heldPackets.putIfAbsent(packet.getPacketId(), packet);
  }

  /**
   * Saare held packets return karo — gossip aur bridge upload ke liye.
   *
   * @return held packets ka collection
   */
  public Collection<MeshPacket> getHeldPackets() {
    return heldPackets.values();
  }

  /**
   * Check karo ki device ke paas yeh packet hai ya nahi.
   *
   * @param packetId check karne wala packet ID
   * @return {@code true} agar packet held hai
   */
  public boolean holds(String packetId) {
    return heldPackets.containsKey(packetId);
  }

  /**
   * Kitne packets device ke paas hain.
   *
   * @return packet count
   */
  public int packetCount() {
    return heldPackets.size();
  }

  /**
   * Internet hai ya nahi — bridge upload ke liye check hota hai.
   *
   * @return {@code true} agar internet connected hai
   */
  public boolean hasInternet() {
    return hasInternet;
  }

  /**
   * Mesh reset hone par device ke saare packets aur acks clear karo.
   */
  public void clear() {
    heldPackets.clear();
    heldAcks.clear();
  }

  /**
   * Ek ack store karo. Idempotent — same ack dobara overwrite nahi hoga.
   * Key {@code packetId|receiverVpa} hai isliye ek device multiple receivers ke acks rakh sakta hai.
   *
   * @param ack jo ack store karna hai
   */
  public void holdAck(AckPacket ack) {
    String key = ack.getPacketId() + "|" + ack.getReceiverVpa();
    heldAcks.putIfAbsent(key, ack);
  }

  /**
   * Check karo ki is device ke paas kisi specific packet ka ack hai ya nahi.
   *
   * @param packetId payment packet ID
   * @param receiverVpa ack karne wale receiver ka VPA
   * @return {@code true} agar ack held hai
   */
  public boolean holdsAck(String packetId, String receiverVpa) {
    return heldAcks.containsKey(packetId + "|" + receiverVpa);
  }

  /**
   * Saare held acks return karo — gossip propagation ke liye.
   *
   * @return ack packets ka collection
   */
  public Collection<AckPacket> getHeldAcks() {
    return heldAcks.values();
  }

  /**
   * Kitne acks device ke paas hain.
   *
   * @return ack count
   */
  public int ackCount() {
    return heldAcks.size();
  }
}
