package com.upimesh.repository;

import com.upimesh.entity.BridgeNode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 *  Spring Data JPA repo for BridgeNode.
 */
@Repository
public interface BridgeNodeRepository extends JpaRepository<BridgeNode, String> {

    /** All non-revoked bridges (for dashboard display). */
    List<BridgeNode> findByRevokedFalse();

    /** All revoked bridges. */
    List<BridgeNode> findByRevokedTrue();
}