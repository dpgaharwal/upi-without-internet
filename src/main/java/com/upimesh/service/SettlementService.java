package com.upimesh.service;

import com.upimesh.entity.Account;
import com.upimesh.entity.PaymentInstruction;
import com.upimesh.entity.Transaction;
import com.upimesh.enums.Status;
import com.upimesh.repository.AccountRepository;
import com.upimesh.repository.TransactionRepository;
import java.math.BigDecimal;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Actual ledger update yahan hota hai — paisa sender se receiver ko jaata hai.
 *
 * <p>Pura operation ek DB transaction mein wrapped hai: ya to debit aur credit
 * dono hote hain, ya koi bhi nahi hota.
 *
 * <p>{@code Account} pe {@code @Version} column optimistic locking deta hai.
 * Agar do threads somehow idempotency layer se nikal ke ek saath same account
 * debit karne ki koshish karein, to doosra {@code OptimisticLockException}
 * throw karega — balance corrupt nahi hoga. Defense in depth.
 *
 * <p>Balance touch karne se pehle {@link SpendTokenService#consume} call hota hai.
 * Agar token missing, already consumed, expired, ya amount mismatch ho to
 * REJECTED transaction record hota hai aur koi paisa nahi hilta.
 */
@Service
@Slf4j
public class SettlementService {

  @Autowired private AccountRepository accounts;
  @Autowired private TransactionRepository transactions;
  @Autowired private SpendTokenService spendTokenService; // NEW

  /**
   * Payment instruction settle karo — spend token validate karo, balance check karo,
   * debit/credit atomically karo, aur transaction record save karo.
   *
   * @param instruction decrypted payment details
   * @param packetHash  SHA-256 of ciphertext — idempotency aur audit ke liye
   * @param bridgeNodeId jis bridge ne packet upload kiya
   * @param hopCount    kitne hops mein packet aaya (analytics)
   * @return saved {@link Transaction} — {@code SETTLED} ya {@code REJECTED} status ke saath
   */
  @Transactional
  public Transaction settle(
          PaymentInstruction instruction, String packetHash,
          String bridgeNodeId, int hopCount) {

    Account sender = accounts
            .findById(instruction.getSenderVpa())
            .orElseThrow(() -> new IllegalArgumentException(
                    "Unknown sender VPA: " + instruction.getSenderVpa()));

    Account receiver = accounts
            .findById(instruction.getReceiverVpa())
            .orElseThrow(() -> new IllegalArgumentException(
                    "Unknown receiver VPA: " + instruction.getReceiverVpa()));

    BigDecimal amount = instruction.getAmount();
    if (amount.signum() <= 0) {
      throw new IllegalArgumentException("Amount must be positive");
    }

    SpendTokenService.ConsumeResult tokenResult = spendTokenService.consume(
            instruction.getSpendTokenNonce(),
            instruction.getSenderVpa(),
            amount,
            packetHash);

    if (!tokenResult.success()) {
      log.warn("Token validation failed for packet {}: {}",
              packetHash.substring(0, 12) + "...", tokenResult.reason());
      return recordRejected(instruction, packetHash, bridgeNodeId, hopCount,
              "token_rejected: " + tokenResult.reason());
    }

    if (sender.getBalance().compareTo(amount) < 0) {
      log.warn("Insufficient balance: {} has ₹{}, tried to send ₹{}",
              sender.getVpa(), sender.getBalance(), amount);
      return recordRejected(instruction, packetHash, bridgeNodeId, hopCount,
              "insufficient_balance");
    }

    sender.setBalance(sender.getBalance().subtract(amount));
    receiver.setBalance(receiver.getBalance().add(amount));
    accounts.save(sender);
    accounts.save(receiver);

    Transaction tx = new Transaction();
    tx.setPacketHash(packetHash);
    tx.setSenderVpa(instruction.getSenderVpa());
    tx.setReceiverVpa(instruction.getReceiverVpa());
    tx.setAmount(amount);
    tx.setSignedAt(Instant.ofEpochMilli(instruction.getSignedAt()));
    tx.setSettledAt(Instant.now());
    tx.setBridgeNodeId(bridgeNodeId);
    tx.setHopCount(hopCount);
    tx.setStatus(Status.SETTLED);
    transactions.save(tx);

    log.info("SETTLED ₹{} from {} to {} (packet={}, bridge={}, hops={})",
            amount, sender.getVpa(), receiver.getVpa(),
            packetHash.substring(0, 12) + "...", bridgeNodeId, hopCount);

    return tx;
  }

  /**
   * REJECTED transaction record karo bina koi paisa move kiye.
   * Audit trail ke liye reason log kiya jaata hai.
   */
  private Transaction recordRejected(
          PaymentInstruction instruction, String packetHash,
          String bridgeNodeId, int hopCount, String reason) {

    Transaction tx = new Transaction();
    tx.setPacketHash(packetHash);
    tx.setSenderVpa(instruction.getSenderVpa());
    tx.setReceiverVpa(instruction.getReceiverVpa());
    tx.setAmount(instruction.getAmount());
    tx.setSignedAt(Instant.ofEpochMilli(instruction.getSignedAt()));
    tx.setSettledAt(Instant.now());
    tx.setBridgeNodeId(bridgeNodeId);
    tx.setHopCount(hopCount);
    tx.setStatus(Status.REJECTED);
    transactions.save(tx);

    log.warn("REJECTED: {}", reason);
    return tx;
  }
}