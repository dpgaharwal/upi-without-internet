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

@Entity
@Table(name = "accounts")
@Getter
@Setter
@NoArgsConstructor
public class Account {

  @Id private String vpa;

  @Column(nullable = false)
  private String holderName;

  @Column(nullable = false, precision = 19, scale = 2)
  private BigDecimal balance;

  @Version private Long version;

  public Account(String vpa, String holderName, BigDecimal balance) {
    this.vpa = vpa;
    this.holderName = holderName;
    this.balance = balance;
  }
}
