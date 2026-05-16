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

/**
 * In-process mesh simulator — virtual devices aur gossip propagation manage karta hai.
 *
 * <p>Real system mein yeh sab physical Android phones pe hota Android BLE GATT ke zariye.
 * Yahan sab kuch ek JVM ke andar simulate hota hai demo ke liye — koi hardware nahi chahiye.
 *
 * <p>Default 5 devices:
 * <ul>
 *   <li>{@code phone-shubham} — sender (no internet)</li>
 *   <li>{@code phone-stranger1/2/3} — intermediate hops (no internet)</li>
 *   <li>{@code phone-bridge} — internet-connected bridge node</li>
 * </ul>
 */
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

  /**
   * Kisi device pe ek packet inject karo — payment flow ka starting point.
   *
   * @param senderDeviceId jis device pe packet start hoga
   * @param packet         inject karne wala packet
   * @throws IllegalArgumentException agar device ID unknown hai
   */
  public void inject(String senderDeviceId, MeshPacket packet) {
    VirtualDevice sender = devices.get(senderDeviceId);
    if (sender == null) throw new IllegalArgumentException("Unknown device: " + senderDeviceId);
    sender.hold(packet);
    log.info("Packet {} injected at {} (TTL={})",
            packet.getPacketId().substring(0, 8), senderDeviceId, packet.getTtl());
  }

  /**
   * Ek gossip round simulate karo — har device jo packet hold kar raha hai woh
   * baaki saare devices ko bhejta hai (TTL > 0 wale packets hi).
   * Har copy pe TTL ek se kam hota hai.
   *
   * @return gossip result — kitne transfers hue aur har device pe packet count
   */
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
   * Internet-connected devices se saare packets collect karo server upload ke liye.
   * Har upload ke saath HMAC signature attach hoti hai — bridge identity verify karne ke liye.
   * Agar bridge registered nahi hai to auto-register hota hai demo ke liye.
   *
   * @return bridge uploads ki list, har ek mein packet aur uski HMAC signature
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
   * Bridge node ke HMAC secret se ciphertext sign karo.
   * Agar bridge registered nahi hai to pehle deterministic demo secret se auto-register karo
   * taaki simulator manually register kiye bina kaam kare.
   * Production mein: bridge ka secret provisioning ke waqt set hota hai.
   *
   * @param nodeId     bridge ka device ID
   * @param ciphertext sign karne wala ciphertext
   * @return base64-encoded HMAC signature, ya empty string agar failure
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

  /**
   * Check karo ki yeh bridge node registered hai ya nahi.
   *
   * @param nodeId check karne wala node ID
   * @return {@code true} agar registered hai
   */
  private boolean bridgeNodeRegistered(String nodeId) {
    return bridgeAuthService.listAll().stream()
            .anyMatch(n -> n.getNodeId().equals(nodeId));
  }

  /**
   * Har device pe abhi kitne packets hain uska snapshot lo — dashboard ke liye.
   *
   * @return deviceId to packet count ka map
   */
  public Map<String, Integer> snapshotMap() {
    Map<String, Integer> m = new LinkedHashMap<>();
    for (VirtualDevice d : devices.values()) {
      m.put(d.getDeviceId(), d.packetCount());
    }
    return m;
  }

  /** Mesh reset karo — saare devices ke packets aur acks clear ho jaate hain. */
  public void resetMesh() {
    devices.values().forEach(VirtualDevice::clear);
  }

  /**
   * Gossip round ka result.
   *
   * @param transfers    kitne packet transfers hue
   * @param deviceCounts har device pe packet count
   */
  public record GossipResult(int transfers, Map<String, Integer> deviceCounts) {}

  /**
   * Bridge upload — ek packet aur uski HMAC signature.
   *
   * @param bridgeNodeId upload karne wala bridge
   * @param packet       upload karne wala mesh packet
   * @param hmacSignature ciphertext ka HMAC-SHA256 signature
   */
  public record BridgeUpload(String bridgeNodeId, MeshPacket packet, String hmacSignature) {}
}
