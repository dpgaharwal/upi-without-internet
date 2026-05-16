package com.upimesh.repository;

import com.upimesh.entity.Transaction;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * {@link Transaction} entity ke liye Spring Data JPA repository.
 *
 * <p>Dashboard pe latest transactions dikhane ke liye ek simple custom
 * method hai — baaki sab JPA ke built-in methods se handle hota hai.
 */
@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

  /**
   * Dashboard ke liye latest 20 transactions descending order mein.
   *
   * @return last 20 transactions, newest pehle
   */
  List<Transaction> findTop20ByOrderByIdDesc();
}
