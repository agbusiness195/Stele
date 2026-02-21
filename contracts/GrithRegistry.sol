// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GrithRegistry
 * @author Grith Protocol
 * @notice On-chain registry for anchoring and verifying covenant constraints.
 * @dev Implements the interface defined by @grith/evm's GRITH_REGISTRY_ABI.
 *
 * Each covenant is identified by a unique bytes32 `covenantId`. An anchor
 * stores the constraints hash, issuer, beneficiary, and timestamp. Once
 * anchored, a covenant can be verified by any party. Only the original
 * issuer may revoke an anchor.
 *
 * The contract is intentionally minimal and ownerless -- there is no admin
 * key, no upgrade proxy, and no pause mechanism. Immutability of the
 * registry logic is a design goal aligned with the Grith protocol's
 * trust model.
 */
contract GrithRegistry {
    // ─── Storage ────────────────────────────────────────────────────────────────

    /**
     * @notice On-chain representation of a covenant anchor.
     * @param constraintsHash Keccak-256 hash of the covenant's constraint document.
     * @param issuer          Address that created (and may revoke) the anchor.
     * @param beneficiary     Address that the covenant protects.
     * @param timestamp       Unix timestamp supplied by the issuer at anchor time.
     * @param exists          Sentinel flag; true while the anchor is live.
     */
    struct Anchor {
        bytes32 constraintsHash;
        address issuer;
        address beneficiary;
        uint256 timestamp;
        bool exists;
    }

    /// @notice Mapping from covenant ID to its anchor data.
    mapping(bytes32 => Anchor) public anchors;

    /// @notice Total number of covenants that have been successfully anchored.
    uint256 private _anchorCount;

    // ─── Events ─────────────────────────────────────────────────────────────────

    /**
     * @notice Emitted when a new covenant is anchored on-chain.
     * @param covenantId      Unique identifier for the covenant.
     * @param constraintsHash Hash of the constraint document.
     * @param issuer          Address that anchored the covenant.
     * @param beneficiary     Beneficiary address of the covenant.
     * @param timestamp       Issuer-supplied Unix timestamp.
     */
    event CovenantAnchored(
        bytes32 indexed covenantId,
        bytes32 constraintsHash,
        address indexed issuer,
        address indexed beneficiary,
        uint256 timestamp
    );

    /**
     * @notice Emitted when an existing covenant anchor is revoked.
     * @param covenantId Unique identifier for the revoked covenant.
     * @param revoker    Address that revoked the anchor (always the original issuer).
     * @param timestamp  Block timestamp at the time of revocation.
     */
    event CovenantRevoked(
        bytes32 indexed covenantId,
        address indexed revoker,
        uint256 timestamp
    );

    // ─── Errors ─────────────────────────────────────────────────────────────────

    /// @notice Thrown when attempting to anchor a covenant ID that already exists.
    error AnchorAlreadyExists(bytes32 covenantId);

    /// @notice Thrown when the caller is not the expected issuer.
    error CallerNotIssuer(address caller, address expectedIssuer);

    /// @notice Thrown when the supplied timestamp is in the future.
    error TimestampInFuture(uint256 supplied, uint256 blockTimestamp);

    /// @notice Thrown when querying an anchor that does not exist.
    error AnchorNotFound(bytes32 covenantId);

    /// @notice Thrown when batch arrays have mismatched lengths.
    error ArrayLengthMismatch();

    // ─── Core Functions ─────────────────────────────────────────────────────────

    /**
     * @notice Anchor a new covenant on-chain.
     * @dev The caller must be the `issuer`. The `timestamp` must not exceed
     *      `block.timestamp` to prevent future-dating. Reverts if the covenant
     *      ID has already been anchored.
     * @param covenantId      Unique 32-byte identifier for the covenant.
     * @param constraintsHash Keccak-256 hash of the covenant's constraint document.
     * @param issuer          Address credited as the covenant creator.
     * @param beneficiary     Address the covenant protects.
     * @param timestamp       Unix timestamp of anchor creation (must be <= block.timestamp).
     */
    function anchor(
        bytes32 covenantId,
        bytes32 constraintsHash,
        address issuer,
        address beneficiary,
        uint256 timestamp
    ) external {
        if (anchors[covenantId].exists) {
            revert AnchorAlreadyExists(covenantId);
        }
        if (msg.sender != issuer) {
            revert CallerNotIssuer(msg.sender, issuer);
        }
        if (timestamp > block.timestamp) {
            revert TimestampInFuture(timestamp, block.timestamp);
        }

        anchors[covenantId] = Anchor({
            constraintsHash: constraintsHash,
            issuer: issuer,
            beneficiary: beneficiary,
            timestamp: timestamp,
            exists: true
        });

        unchecked {
            _anchorCount++;
        }

        emit CovenantAnchored(covenantId, constraintsHash, issuer, beneficiary, timestamp);
    }

    /**
     * @notice Check whether a covenant has been anchored.
     * @param covenantId The covenant identifier to look up.
     * @return True if an anchor exists for this covenant ID, false otherwise.
     */
    function verify(bytes32 covenantId) external view returns (bool) {
        return anchors[covenantId].exists;
    }

    /**
     * @notice Retrieve the full anchor data for a covenant.
     * @dev Reverts if the anchor does not exist.
     * @param covenantId The covenant identifier to look up.
     * @return constraintsHash Hash of the constraint document.
     * @return issuer          Address that created the anchor.
     * @return beneficiary     Beneficiary address.
     * @return timestamp       Issuer-supplied Unix timestamp.
     */
    function getAnchor(bytes32 covenantId)
        external
        view
        returns (
            bytes32 constraintsHash,
            address issuer,
            address beneficiary,
            uint256 timestamp
        )
    {
        Anchor storage a = anchors[covenantId];
        if (!a.exists) {
            revert AnchorNotFound(covenantId);
        }
        return (a.constraintsHash, a.issuer, a.beneficiary, a.timestamp);
    }

    /**
     * @notice Revoke an existing covenant anchor.
     * @dev Only the original issuer may revoke. The anchor data is deleted and
     *      the anchor count is decremented. Emits {CovenantRevoked}.
     * @param covenantId The covenant identifier to revoke.
     */
    function revoke(bytes32 covenantId) external {
        Anchor storage a = anchors[covenantId];
        if (!a.exists) {
            revert AnchorNotFound(covenantId);
        }
        if (msg.sender != a.issuer) {
            revert CallerNotIssuer(msg.sender, a.issuer);
        }

        delete anchors[covenantId];

        unchecked {
            _anchorCount--;
        }

        emit CovenantRevoked(covenantId, msg.sender, block.timestamp);
    }

    // ─── Batch Functions ────────────────────────────────────────────────────────

    /**
     * @notice Anchor multiple covenants in a single transaction.
     * @dev All arrays must have the same length. Each entry is validated
     *      independently via the same rules as {anchor}. If any entry
     *      reverts, the entire batch reverts.
     * @param covenantIds      Array of unique covenant identifiers.
     * @param constraintsHashes Array of constraint document hashes.
     * @param issuers          Array of issuer addresses.
     * @param beneficiaries    Array of beneficiary addresses.
     * @param timestamps       Array of Unix timestamps.
     */
    function anchorBatch(
        bytes32[] calldata covenantIds,
        bytes32[] calldata constraintsHashes,
        address[] calldata issuers,
        address[] calldata beneficiaries,
        uint256[] calldata timestamps
    ) external {
        uint256 length = covenantIds.length;
        if (
            constraintsHashes.length != length ||
            issuers.length != length ||
            beneficiaries.length != length ||
            timestamps.length != length
        ) {
            revert ArrayLengthMismatch();
        }

        for (uint256 i; i < length; ) {
            bytes32 id = covenantIds[i];

            if (anchors[id].exists) {
                revert AnchorAlreadyExists(id);
            }
            if (msg.sender != issuers[i]) {
                revert CallerNotIssuer(msg.sender, issuers[i]);
            }
            if (timestamps[i] > block.timestamp) {
                revert TimestampInFuture(timestamps[i], block.timestamp);
            }

            anchors[id] = Anchor({
                constraintsHash: constraintsHashes[i],
                issuer: issuers[i],
                beneficiary: beneficiaries[i],
                timestamp: timestamps[i],
                exists: true
            });

            emit CovenantAnchored(
                id,
                constraintsHashes[i],
                issuers[i],
                beneficiaries[i],
                timestamps[i]
            );

            unchecked {
                ++i;
            }
        }

        unchecked {
            _anchorCount += length;
        }
    }

    /**
     * @notice Verify multiple covenants in a single call.
     * @param covenantIds Array of covenant identifiers to check.
     * @return results Array of booleans; true if the corresponding anchor exists.
     */
    function verifyBatch(bytes32[] calldata covenantIds)
        external
        view
        returns (bool[] memory results)
    {
        uint256 length = covenantIds.length;
        results = new bool[](length);

        for (uint256 i; i < length; ) {
            results[i] = anchors[covenantIds[i]].exists;
            unchecked {
                ++i;
            }
        }
    }

    // ─── Utility Functions ──────────────────────────────────────────────────────

    /**
     * @notice Compute a deterministic Keccak-256 hash of anchor data.
     * @dev This is a pure function useful for off-chain verification and
     *      pre-computing anchor hashes. The encoding matches abi.encodePacked
     *      with all five fields concatenated in order.
     * @param covenantId      Covenant identifier.
     * @param constraintsHash Constraint document hash.
     * @param issuer          Issuer address.
     * @param beneficiary     Beneficiary address.
     * @param timestamp       Unix timestamp.
     * @return The Keccak-256 hash of the tightly packed anchor data.
     */
    function computeAnchorHash(
        bytes32 covenantId,
        bytes32 constraintsHash,
        address issuer,
        address beneficiary,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(covenantId, constraintsHash, issuer, beneficiary, timestamp)
        );
    }

    /**
     * @notice Return the current number of live (non-revoked) anchors.
     * @return The total anchor count.
     */
    function anchorCount() external view returns (uint256) {
        return _anchorCount;
    }
}
