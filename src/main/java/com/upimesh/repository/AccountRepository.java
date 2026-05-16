package com.upimesh.repository;

import com.upimesh.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * {@link Account} entity ke liye Spring Data JPA repository.
 *
 * <p>Primary key {@code vpa} (String) hai. Built-in methods se hi kaam chal jaata hai —
 * koi custom query nahi chahiye abhi ke liye.
 */
@Repository
public interface AccountRepository extends JpaRepository<Account, String> {}
