package com.upimesh.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.math.BigDecimal;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Ek UPI account ko represent karta hai.
 *
 * <p>Primary key {@code vpa} hai (Virtual Payment Address, jaise
 * {@code ShubhamTiwari@demo}). {@code balance} field pe {@code @Version}
 * annotation hai jo JPA optimistic locking deta hai — agar do threads ek
 * hi account ka balance simultaneously update karne ki koshish karein to
 * doosra wala {@code OptimisticLockException} throw karega, balance
 * corrupt nahi hoga.
 */
@Entity
@Table(name = "accounts")
@Getter
@Setter
@NoArgsConstructor
public class Account {

  /** Virtual Payment Address — primary key, jaise {@code ShubhamTiwari@demo}. */
  @Id private String vpa;

  /** Account holder ka naam. */
  @Column(nullable = false)
  private String holderName;

  /** Current balance rupees mein. Settlement ke waqt atomically update hota hai. */
  @Column(nullable = false, precision = 19, scale = 2)
  private BigDecimal balance;

  /**
   * JPA optimistic lock version. Har update pe increment hota hai.
   * Concurrent balance update hone par {@code OptimisticLockException} throw hoti hai.
   */
  @Version private Long version;

  public Account(String vpa, String holderName, BigDecimal balance) {
    this.vpa = vpa;
    this.holderName = holderName;
    this.balance = balance;
  }
}
