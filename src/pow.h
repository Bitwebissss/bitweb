// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <cstdint>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
// unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** LWMA3 diff algo Bitweb Params */
unsigned int Lwma3CalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params&);

/**
 * [Bitweb] Cached variant of CheckProofOfWork() for a full header
 * (CBlockHeader, or CBlock via inheritance). Argon2id is memory-hard and
 * expensive relative to upstream's SHA256d, and the same header's PoW is
 * legitimately re-checked at several independent points in the codebase
 * (headers-sync batch check, CheckBlockHeader() on header acceptance and
 * again on block acceptance, and disk re-reads in BlockManager::ReadBlock).
 * This lets every one of those call sites share one process-lifetime,
 * positive-only result cache instead of each re-hashing from scratch.
 *
 * Safety argument (see pow.cpp for the cache implementation):
 * - Positive-only: a failed check is never cached, so a cache hit can only
 *   ever mean "this exact header content already passed
 *   CheckProofOfWork(GetArgon2idPoWHash(), ...) at least once, at some
 *   point in this process's lifetime". A miss always falls back to a full,
 *   honest recompute -- behavior on miss is identical to having no cache,
 *   so this can only remove redundant work, never weaken validation.
 * - Keyed on header.GetHash() (cheap SHA256d), not on the Argon2id result,
 *   so even computing the cache key never requires the expensive hash.
 * - Deliberately process-global and not tied to any peer/session/sync
 *   phase -- once a header is verified once, from anywhere, every other
 *   call site benefits, including a PRESYNC that had to restart with a
 *   different peer, or a disk re-read years later.
 *
 * @param[in] header Header (or block, via CBlockHeader base) to verify;
 *                    keyed by header.GetHash().
 * @param[in] params Consensus params to check the PoW against.
 * @return true if PoW is valid (cache hit, or freshly verified and now
 *         cached); false if verification failed. A false result is never
 *         cached, so a failed check here is always a full, honest check.
 */
bool CheckProofOfWorkCached(const CBlockHeader& header, const Consensus::Params& params);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits);

#endif // BITCOIN_POW_H
