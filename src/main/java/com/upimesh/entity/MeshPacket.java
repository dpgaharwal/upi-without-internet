package com.upimesh.entity;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * The over-the-wire format. This is what hops from phone to phone via Bluetooth.
 *
 * <p>The intermediate phones can read the OUTER fields (packetId, ttl, createdAt) because they need
 * them for routing and dedup. They CANNOT read `ciphertext` — that's encrypted with the server's
 * public key.
 *
 * <p>NOTE on outer-field tampering: A malicious intermediate could change `packetId` or
 * `createdAt`. That's why we use the ciphertext's hash (not packetId) as the idempotency key on the
 * server. The ciphertext is authenticated by hybrid encryption, so any tampering inside the
 * encrypted blob is detected on decryption.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class MeshPacket {
  @NotBlank private String packetId;

  @Min(0)
  private int ttl;

  @NotNull private Long createdAt;

  @NotBlank private String ciphertext;
}
