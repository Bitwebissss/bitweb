// Copyright (c) 2026-present The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_CACHE_H
#define BITCOIN_POW_CACHE_H

#include <consensus/params.h>
#include <cuckoocache.h>
#include <uint256.h>
#include <util/hasher.h>

#include <mutex>
#include <shared_mutex>

class CBlockHeader;

/**
 * [Bitweb] Positive-only result cache used by CheckProofOfWorkCached()
 * (pow.h/pow.cpp) to avoid redundant Argon2id recomputation for a header
 * whose PoW has already been verified once in this process.
 *
 * Deliberately a plain public class with no process-global state of its
 * own -- the process-lifetime singleton instance lives in pow.cpp
 * (GetHeaderPoWCache()), not here. Keeping the class itself free-standing
 * lets test/fuzz code construct independent local instances directly
 * (same pattern as CuckooCache::cache itself, and as SignatureCache in
 * script/sigcache.h) without needing to reach into pow.cpp's internals or
 * go through any header/consensus-params machinery -- the cache only
 * knows about uint256 keys, nothing about what they mean.
 *
 * Safety argument (see pow.h's CheckProofOfWorkCached() doc comment for
 * the full picture of how this is used):
 * - Get() is read-only; Set() is the only mutator, so callers control
 *   entirely when something becomes a "hit" for someone else.
 * - Thread-safe for concurrent Get() calls, and for Get()/Set() run
 *   concurrently with each other, via shared_mutex (Get: shared_lock,
 *   Set: unique_lock) -- matching CuckooCache::cache's own contract that
 *   writes require external synchronization against reads.
 */
class HeaderPoWCache
{
private:
    typedef CuckooCache::cache<uint256, SignatureCacheHasher> map_type;
    mutable map_type m_cache;
    mutable std::shared_mutex m_mutex;

public:
    explicit HeaderPoWCache(size_t max_size_bytes = 1 << 26) // default: 64 MiB == 2,097,152 entries
    {
        m_cache.setup_bytes(max_size_bytes);
    }

    HeaderPoWCache(const HeaderPoWCache&) = delete;
    HeaderPoWCache& operator=(const HeaderPoWCache&) = delete;

    bool Get(const uint256& hash) const
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_cache.contains(hash, /*erase=*/false);
    }

    void Set(const uint256& hash)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_cache.insert(hash);
    }
};

/**
 * Process-lifetime shared instance used by CheckProofOfWorkCached(). Every
 * caller (validation.cpp's CheckBlockHeader()/CHeaderPoWCheck,
 * node/blockstorage.cpp's ReadBlock(), and any future caller) shares this
 * one cache. Sized for ~2.1M headers (2^21 entries, 64 MiB at
 * sizeof(uint256)=32 bytes/entry) -- see pow.cpp for the full sizing
 * rationale.
 */
HeaderPoWCache& GetHeaderPoWCache();

/**
 * [Bitweb] Cached variant of CheckProofOfWork() (pow.h) for a full header
 * (CBlockHeader, or CBlock via inheritance). Argon2id is memory-hard and
 * expensive relative to upstream's SHA256d, and the same header's PoW is
 * legitimately re-checked at several independent points in the codebase
 * (headers-sync batch check, CheckBlockHeader() on header acceptance and
 * again on block acceptance, and disk re-reads in BlockManager::ReadBlock).
 * This lets every one of those call sites share one process-lifetime,
 * positive-only result cache instead of each re-hashing from scratch.
 *
 * Safety argument (see pow_cache.cpp for the implementation):
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

#endif // BITCOIN_POW_CACHE_H
