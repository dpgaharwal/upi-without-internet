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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class MeshSimulatorService {

  @Autowired
  private BridgeAuthService bridgeAuthService;

  public MeshSimulatorService() {
    seedDefaultDevices();
  }

  private void seedDefaultDevices() {
    devices.put("phone-shubham",   new VirtualDevice("phone-shubham",   false));
    devices.put("phone-stranger1", new VirtualDevice("phone-stranger1", false));
    devices.put("phone-stranger2", new VirtualDevice("phone-stranger2", false));
    devices.put("phone-stranger3", new VirtualDevice("phone-stranger3", false));
    devices.put("phone-bridge",    new VirtualDevice("phone-bridge",    true));
  }

  private final Map<String, VirtualDevice> devices = new ConcurrentHashMap<>();

  public Collection<VirtualDevice> getDevices() { return devices.values(); }
  public VirtualDevice getDevice(String id)      { return devices.get(id); }

  public void inject(String senderDeviceId, MeshPacket packet) {
    VirtualDevice sender = devices.get(senderDeviceId);
    if (sender == null) throw new IllegalArgumentException("Unknown device: " + senderDeviceId);
    sender.hold(packet);
    log.info("Packet {} injected at {} (TTL={})",
            packet.getPacketId().substring(0, 8), senderDeviceId, packet.getTtl());
  }

  public GossipResult gossipOnce() {
    int transfers = 0;
    List<VirtualDevice> deviceList = new ArrayList<>(devices.values());

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
          // hopCount NOT set — derived server-side from time, not from outer envelope

          dst.hold(copy);
          transfers++;
        }
      }
    }

    log.info("Gossip round complete: {} packet transfers", transfers);
    return new GossipResult(transfers, snapshotMap());
  }

  /**
   * Collect all packets from internet-connected devices for flushing.
   *
   * Problem 7 change: each BridgeUpload now carries an HMAC signature.
   * The simulator acts as a "legitimate bridge" that has registered with
   * nodeId = deviceId (e.g. "phone-bridge") and knows the HMAC secret.
   *
   * If the bridge device is not registered, the upload carries an empty
   * signature and will be rejected by /api/bridge/ingest (unless you use
   * the internal bridge.ingest() path which skips auth — that's intentional
   * so the /api/mesh/flush endpoint can auto-register the demo bridge).
   */
  public List<BridgeUpload> collectBridgeUploads() {
    List<BridgeUpload> out = new ArrayList<>();
    for (VirtualDevice d : devices.values()) {
      if (!d.hasInternet()) continue;
      for (MeshPacket pkt : d.getHeldPackets()) {
        String signature = computeSignatureForUpload(d.getDeviceId(), pkt.getCiphertext());
        out.add(new BridgeUpload(d.getDeviceId(), pkt, signature));
      }
    }
    return out;
  }

  /**
   * Sign the ciphertext with the HMAC secret of the bridge node.
   * If the bridge is not registered, auto-register it with a demo secret
   * so the simulator "just works" out of the box without manual registration.
   *
   * In production: the bridge would have its secret pre-provisioned.
   * Here: we auto-register on first flush so the demo is frictionless.
   */
  private String computeSignatureForUpload(String nodeId, String ciphertext) {
    try {
      // Auto-register the demo bridge if not yet registered
      // (so the simulator works without manual setup)
      if (!bridgeNodeRegistered(nodeId)) {
        // Generate a deterministic demo secret: SHA-256(nodeId) → base64
        // Real bridges would have a proper random secret set at provisioning
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] secretBytes = md.digest((nodeId + "-demo-secret").getBytes());
        // Pad to 32 bytes (SHA-256 already produces 32)
        String secretBase64 = java.util.Base64.getEncoder().encodeToString(secretBytes);
        bridgeAuthService.register(nodeId, secretBase64);
        log.info("Auto-registered demo bridge: nodeId={}", nodeId);
      }

      // Retrieve the stored secret and compute HMAC
      com.upimesh.entity.BridgeNode node =
              bridgeAuthService.listAll().stream()
                      .filter(n -> n.getNodeId().equals(nodeId))
                      .findFirst().orElse(null);

      if (node == null || node.isRevoked()) {
        log.warn("Bridge {} is revoked or missing — upload will fail auth", nodeId);
        return "";
      }

      return bridgeAuthService.computeHmac(ciphertext, node.getHmacSecret());

    } catch (Exception e) {
      log.error("Failed to compute upload signature for bridge {}: {}", nodeId, e.getMessage());
      return "";
    }
  }

  private boolean bridgeNodeRegistered(String nodeId) {
    return bridgeAuthService.listAll().stream()
            .anyMatch(n -> n.getNodeId().equals(nodeId));
  }

  public Map<String, Integer> snapshotMap() {
    Map<String, Integer> m = new LinkedHashMap<>();
    for (VirtualDevice d : devices.values()) {
      m.put(d.getDeviceId(), d.packetCount());
    }
    return m;
  }

  public void resetMesh() {
    devices.values().forEach(VirtualDevice::clear);
  }

  public record GossipResult(int transfers, Map<String, Integer> deviceCounts) {}
  public record BridgeUpload(String bridgeNodeId, MeshPacket packet, String hmacSignature) {}
}
