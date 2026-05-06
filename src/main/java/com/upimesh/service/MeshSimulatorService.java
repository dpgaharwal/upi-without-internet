package com.upimesh.service;

import com.upimesh.entity.MeshPacket;
import com.upimesh.entity.VirtualDevice;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class MeshSimulatorService {

  public MeshSimulatorService() {
    seedDefaultDevices();
  }

  public Collection<VirtualDevice> getDevices() {
    return devices.values();
  }

  public VirtualDevice getDevice(String id) {
    return devices.get(id);
  }

  private void seedDefaultDevices() {
    devices.put("phone-shubham", new VirtualDevice("phone-shubham", false));
    devices.put("phone-stranger1", new VirtualDevice("phone-stranger1", false));
    devices.put("phone-stranger2", new VirtualDevice("phone-stranger2", false));
    devices.put("phone-stranger3", new VirtualDevice("phone-stranger3", false));
    devices.put("phone-bridge", new VirtualDevice("phone-bridge", true));
  }

  private final Map<String, VirtualDevice> devices = new ConcurrentHashMap<>();

  /** Sender drops a packet into the mesh by handing it to their own device. */
  public void inject(String senderDeviceId, MeshPacket packet) {
    VirtualDevice sender = devices.get(senderDeviceId);

    if (sender == null) {
      throw new IllegalArgumentException("Unknown device: " + senderDeviceId);
    }
    sender.hold(packet);
    log.info(
        "Packet {} injected at {} (TTL={})",
        packet.getPacketId().substring(0, 8),
        senderDeviceId,
        packet.getTtl());
  }

  /**
   * One round of gossip. Every device shares everything it has with every other device. TTL is
   * decremented per hop; packets at TTL 0 stay where they are but are not forwarded further.
   *
   * <p>Real BLE gossip would be pair-by-pair when devices come into range. For the demo we let
   * everyone gossip with everyone in one round, which is equivalent to "fast-forward N rounds of
   * pairwise gossip".
   */
  public GossipResult gossipOnce() {
    int transfers = 0;
    List<VirtualDevice> deviceList = new ArrayList<>(devices.values());

    // Snapshot what each device holds at the start of this round, so
    // we don't gossip the same packet through 5 devices in 1 step.
    Map<String, List<MeshPacket>> snapshot = new HashMap<>();
    for (VirtualDevice d : deviceList) {
      snapshot.put(d.getDeviceId(), new ArrayList<>(d.getHeldPackets()));
    }

    for (VirtualDevice src : deviceList) {
      for (MeshPacket pkt : snapshot.get(src.getDeviceId())) {
        if (pkt.getTtl() <= 0) continue;
        for (VirtualDevice dst : deviceList) {
          if (dst == src) continue;
          if (dst.holds(pkt.getPacketId())) continue;
          MeshPacket copy = new MeshPacket();
          copy.setPacketId(pkt.getPacketId());
          copy.setTtl(pkt.getTtl() - 1);
          copy.setCreatedAt(pkt.getCreatedAt());
          copy.setCiphertext(pkt.getCiphertext());
          dst.hold(copy);
          transfers++;
        }
      }
    }

    log.info("Gossip round complete: {} packet transfers", transfers);
    return new GossipResult(transfers, snapshotMap());
  }

  public Map<String, Integer> snapshotMap() {
    Map<String, Integer> m = new LinkedHashMap<>();
    for (VirtualDevice d : devices.values()) {
      m.put(d.getDeviceId(), d.packetCount());
    }
    return m;
  }

  /**
   * Returns all packets held by devices with internet — these are what would be uploaded to the
   * backend the moment they reach connectivity.
   */
  public List<BridgeUpload> collectBridgeUploads() {
    List<BridgeUpload> out = new ArrayList<>();
    for (VirtualDevice d : devices.values()) {
      if (!d.hasInternet()) continue;
      for (MeshPacket pkt : d.getHeldPackets()) {
        out.add(new BridgeUpload(d.getDeviceId(), pkt));
      }
    }
    return out;
  }

  public void resetMesh() {
    devices.values().forEach(VirtualDevice::clear);
  }

  public record GossipResult(int transfers, Map<String, Integer> deviceCounts) {}

  public record BridgeUpload(String bridgeNodeId, MeshPacket packet) {}
}
