// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  VotingLedger
 * @notice On-chain anchor for a post-quantum e-voting system.
 *
 * The contract stores NO plaintext votes.  It records:
 *   • Nullifiers  (bytes32)  – SHA3-256(voter_id_hash)
 *                              where voter_id_hash = SHA3-256(voter_id).
 *                              The double-hash prevents linking the on-chain
 *                              record to the voter; prevents double-voting.
 *   • encVoteHash (bytes32)  – SHA3-256(FHE ciphertext)   tamper evidence
 *   • zkpHash     (bytes32)  – SHA3-256(ZKP proof JSON)   public verifiability
 *   • batchMerkleRoot        – Root of each mined off-chain block's Merkle tree
 *   • resultsHash + PQ sig   – After election closes: ML-DSA-65 sig (off-chain)
 *
 * The heavy cryptography (ML-KEM-768, ML-DSA-65, FHE, ZKP, biometrics) lives
 * entirely in the Python layer.  This contract is the tamper-evident public
 * registry that any third party can audit.
 *
 * Deployment
 * ----------
 * 1. Install Hardhat:  npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
 * 2. Compile:          npx hardhat compile
 * 3. Deploy local:     npx hardhat run scripts/deploy.js --network localhost
 * 4. Deploy Sepolia:   npx hardhat run scripts/deploy.js --network sepolia
 *
 * Constructor argument: the election ID string (e.g. "GeneralElection2024")
 */
contract VotingLedger {

    // ── Immutable state ───────────────────────────────────────────────────────
    address public immutable authority;
    string  public           electionId;

    // ── Mutable state ─────────────────────────────────────────────────────────
    bool    public isOpen;
    uint256 public totalVotes;

    // Nullifier registry — SHA3-256(voter_id_hash)
    // (voter_id_hash is itself SHA3-256(voter_id), so the nullifier is a
    //  double-hash that prevents linking the on-chain record to the voter.)
    mapping(bytes32 => bool) public nullifiers;

    // Per-vote evidence anchored on-chain
    struct VoteEvidence {
        bytes32 nullifier;
        bytes32 encVoteHash;   // SHA3-256(FHE ciphertext)
        bytes32 zkpHash;       // SHA3-256(ZKP proof)
        uint64  timestamp;
    }
    VoteEvidence[] public evidence;

    // Merkle roots from off-chain PQ-blockchain blocks
    bytes32[] public batchMerkleRoots;

    // Finalised result
    bytes32 public resultsHash;
    bytes   public resultsPQSignature;   // raw ML-DSA-65 signature bytes

    // ── Events ────────────────────────────────────────────────────────────────
    event VoteAnchored(
        bytes32 indexed nullifier,
        bytes32         encVoteHash,
        bytes32         zkpHash,
        uint256 indexed voteIndex,
        uint64          timestamp
    );
    event BatchRecorded(
        uint256 indexed batchIndex,
        bytes32         merkleRoot,
        uint256         voteCount
    );
    event ElectionFinalized(
        bytes32 resultsHash,
        uint256 totalVotes,
        uint64  timestamp
    );

    // ── Modifiers ─────────────────────────────────────────────────────────────
    modifier onlyAuthority() {
        require(msg.sender == authority, "Not authority");
        _;
    }
    modifier whenOpen() {
        require(isOpen, "Election closed");
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────
    constructor(string memory _electionId) {
        authority  = msg.sender;
        electionId = _electionId;
        isOpen     = true;
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /**
     * @notice Anchor evidence of a single encrypted vote.
     * @param nullifier    SHA3-256(voter_id_hash)  where voter_id_hash = SHA3-256(voter_id)
     * @param encVoteHash  SHA3-256(FHE BFV ciphertext bytes)
     * @param zkpHash      SHA3-256(ZKP proof JSON bytes)
     */
    function anchorVote(
        bytes32 nullifier,
        bytes32 encVoteHash,
        bytes32 zkpHash
    ) external onlyAuthority whenOpen {
        require(!nullifiers[nullifier], "Double vote");

        nullifiers[nullifier] = true;
        evidence.push(VoteEvidence({
            nullifier:   nullifier,
            encVoteHash: encVoteHash,
            zkpHash:     zkpHash,
            timestamp:   uint64(block.timestamp)
        }));
        totalVotes++;

        emit VoteAnchored(
            nullifier, encVoteHash, zkpHash,
            totalVotes - 1, uint64(block.timestamp)
        );
    }

    /**
     * @notice Record the Merkle root of an off-chain PQ-blockchain block.
     */
    function recordBatch(bytes32 merkleRoot, uint256 voteCount)
        external onlyAuthority
    {
        batchMerkleRoots.push(merkleRoot);
        emit BatchRecorded(batchMerkleRoots.length - 1, merkleRoot, voteCount);
    }

    /**
     * @notice Close the election, anchor the results hash and PQ signature.
     * @param _resultsHash   SHA3-256 of the JSON results dict
     * @param _pqSignature   ML-DSA-65 signature over _resultsHash (raw bytes)
     */
    function finalizeElection(bytes32 _resultsHash, bytes calldata _pqSignature)
        external onlyAuthority whenOpen
    {
        isOpen             = false;
        resultsHash        = _resultsHash;
        resultsPQSignature = _pqSignature;

        emit ElectionFinalized(_resultsHash, totalVotes, uint64(block.timestamp));
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    function getEvidence(uint256 idx)
        external view
        returns (bytes32, bytes32, bytes32, uint64)
    {
        VoteEvidence memory e = evidence[idx];
        return (e.nullifier, e.encVoteHash, e.zkpHash, e.timestamp);
    }

    function getAllMerkleRoots() external view returns (bytes32[] memory) {
        return batchMerkleRoots;
    }

    function isNullifierUsed(bytes32 n) external view returns (bool) {
        return nullifiers[n];
    }
}
