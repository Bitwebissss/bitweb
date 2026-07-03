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

//! Default maximum size of the header proof-of-work verification cache
//! (HeaderPoWCache / GetHeaderPoWCache()), in bytes. 64 MiB == 2,097,152
//! entries at sizeof(uint256)=32 bytes/entry -- see pow_cache.cpp
//! (GetHeaderPoWCache()) for the full sizing rationale. Not required to be
//! a power of two: CuckooCache::setup_bytes()/setup() size their backing
//! vector to exactly the requested element count and index into it via
//! FastRange32 (see cuckoocache.h's compute_hashes() comment), not a
//! bitmask, specifically so an arbitrary size works -- 64 MiB is chosen
//! here purely because it divides evenly into a round entry count, not
//! because a non-power-of-two byte count would misbehave.
//! Overridable at runtime via -headerpowcachesize=<MiB> (see
//! InitHeaderPoWCache() below and node/chainstatemanager_args.cpp); this
//! constant is only the compiled-in fallback used when nothing overrides
//! it (e.g. a bare libbitcoinkernel consumer with no ArgsManager, such as
//! bitcoin-chainstate).
static constexpr size_t DEFAULT_HEADER_POW_CACHE_BYTES{64 << 20}; // 64 MiB

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
    explicit HeaderPoWCache(size_t max_size_bytes = DEFAULT_HEADER_POW_CACHE_BYTES)
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
 * one cache. Defaults to DEFAULT_HEADER_POW_CACHE_BYTES (~2.1M headers,
 * 64 MiB at sizeof(uint256)=32 bytes/entry) unless InitHeaderPoWCache() was
 * called earlier in this process with a different size -- see
 * InitHeaderPoWCache() below for the sizing rationale and override
 * mechanism.
 *
 * Lazily constructed on first call (function-local static, thread-safe
 * init since C++11). Because of this, the size actually used is whatever
 * InitHeaderPoWCache() (if any) set *before* this function's first call
 * anywhere in the process -- any InitHeaderPoWCache() call after that
 * point cannot resize an already-constructed cache (see the assert
 * there).
 */
HeaderPoWCache& GetHeaderPoWCache();

/**
 * Set the size (bytes) that GetHeaderPoWCache()'s process-lifetime cache
 * will be constructed with. Optional: if this is never called, the cache
 * simply uses DEFAULT_HEADER_POW_CACHE_BYTES, which is always the case
 * for a bare libbitcoinkernel consumer that has no ArgsManager/config
 * layer to call this from in the first place (e.g. bitcoin-chainstate) --
 * this function exists purely so an app-level layer that *does* have one
 * (bitwebd's -headerpowcachesize=<MiB>, wired up in
 * node/chainstatemanager_args.cpp) can override the default before the
 * cache is first touched. pow_cache.cpp/pow.cpp are compiled directly
 * into libbitcoinkernel and never call into ArgsManager themselves -- see
 * the app-layer wiring in node/chainstatemanager_args.cpp and init.cpp
 * for how the value gets here without the kernel depending on gArgs.
 *
 * Must be called, if at all, strictly before the first call to
 * GetHeaderPoWCache() (directly, or indirectly via
 * CheckProofOfWorkCached()) anywhere in the process -- asserts otherwise,
 * since a silent no-op there would be a confusing, hard-to-notice bug
 * rather than a loud one. Not thread-safe against concurrent
 * GetHeaderPoWCache() calls; the intended caller is single-threaded
 * process startup code, before any header/block processing begins.
 */
void InitHeaderPoWCache(size_t max_size_bytes);

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
