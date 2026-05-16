package com.upimesh.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Receiver ka signed receipt jo mesh mein reverse direction mein travel karta hai.
 *
 * <p>Flow kuch aisa hai:
 * <ol>
 *   <li>Receiver ka device payment packet receive karta hai (decrypt nahi kar sakta —
 *       woh server ki private key se hi hoga). Lekin packet mila yeh confirm karne ke
 *       liye ek ack sign karta hai.</li>
 *   <li>{@link com.upimesh.service.AckService} receiver ki RSA private key se
 *       {@code packetId|receiverVpa|timestamp} sign karta hai.</li>
 *   <li>Yeh AckPacket mesh mein ulta travel karta hai — receiver se sender ke device tak.</li>
 *   <li>Sender {@link com.upimesh.crypto.ReceiverKeyHolder} se receiver ki public key lekar
 *       signature verify karta hai.</li>
 * </ol>
 *
 * <p>Iska faayda: bina internet ke bhi sender ko confirmation mil jaata hai ki receiver
 * tak packet pahuncha — settlement hone se pehle bhi.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AckPacket {

  /** Original payment packet ka ID jiska yeh ack hai. */
  private String packetId;

  /** Woh VPA jisne yeh ack sign kiya. */
  private String receiverVpa;

  /**
   * RSA-SHA256 signature over: {@code packetId + "|" + receiverVpa + "|" + timestamp}.
   * Base64-encoded. Receiver ki public key se verify hota hai.
   */
  private String signature;

  /** Jab ack create hua epoch milliseconds mein. */
  private long timestamp;

  /**
   * Remaining hops. Har hop pe ek se kam hota hai.
   * Zero hone par aage nahi bheja jaata.
   */
  private int ttl;
}
