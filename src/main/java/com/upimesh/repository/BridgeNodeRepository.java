package com.upimesh.repository;

import com.upimesh.entity.BridgeNode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * {@link BridgeNode} entity ke liye Spring Data JPA repository.
 *
 * <p>Primary key {@code nodeId} (String) hai. Dashboard display ke liye
 * active aur revoked bridges alag-alag fetch karne ke custom methods hain.
 */
@Repository
public interface BridgeNodeRepository extends JpaRepository<BridgeNode, String> {

    /** Dashboard ke liye — sirf active (non-revoked) bridges return karta hai. */
    List<BridgeNode> findByRevokedFalse();

    /** Audit ke liye — sirf revoked bridges return karta hai. */
    List<BridgeNode> findByRevokedTrue();
}