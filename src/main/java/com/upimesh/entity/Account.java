package com.upimesh.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.math.BigDecimal;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "accounts")
@Getter
@Setter
@NoArgsConstructor
@RequiredArgsConstructor
public class Account {

  @Id private String vpa;

  @Column(nullable = false)
  private String holderName;

  @Column(nullable = false, precision = 19, scale = 2)
  private BigDecimal balance;

  @Version private Long version;
}
