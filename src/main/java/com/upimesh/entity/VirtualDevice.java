package com.upimesh.entity;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * A simulated phone in the mesh. Holds packets it has seen.
 *
 * <p>In the real system, this state would be on a physical Android device, with packets exchanged
 * via BLE GATT characteristics.
 */
@AllArgsConstructor
@Getter
@Setter
public class VirtualDevice {

  private final String deviceId;
  private final boolean hasInternet;
  private final Map<String, MeshPacket> heldPackets = new ConcurrentHashMap<>();

  // ack store
  // Key = packetId + "|" + receiverVpa (unique per ack)
  private final Map<String, AckPacket> heldAcks = new ConcurrentHashMap<>();

  public void hold(MeshPacket packet) {
    heldPackets.putIfAbsent(packet.getPacketId(), packet);
  }

  public Collection<MeshPacket> getHeldPackets() {
    return heldPackets.values();
  }

  public boolean holds(String packetId) {
    return heldPackets.containsKey(packetId);
  }

  public int packetCount() {
    return heldPackets.size();
  }

  public boolean hasInternet() {
    return hasInternet;
  }

  public void clear() {
    heldPackets.clear();
    heldAcks.clear(); // also clear acks on mesh reset
  }

  /**
   * Store an ack on this device. Idempotent — same ack won't overwrite.
   * Key is packetId|receiverVpa so one device can hold acks from multiple receivers.
   */
  public void holdAck(AckPacket ack) {
    String key = ack.getPacketId() + "|" + ack.getReceiverVpa();
    heldAcks.putIfAbsent(key, ack);
  }

  public boolean holdsAck(String packetId, String receiverVpa) {
    return heldAcks.containsKey(packetId + "|" + receiverVpa);
  }

  public Collection<AckPacket> getHeldAcks() {
    return heldAcks.values();
  }

  public int ackCount() {
    return heldAcks.size();
  }
}
