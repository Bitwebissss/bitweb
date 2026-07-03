// Copyright (c) 2026-present The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow_cache.h>

#include <pow.h>
#include <primitives/block.h>

#include <atomic>
#include <cassert>

// Size GetHeaderPoWCache()'s cache will be constructed with. Only ever
// written by InitHeaderPoWCache(), and only ever meant to be written once,
// before the first GetHeaderPoWCache() call -- see both functions' doc
// comments in pow_cache.h. Plain std::atomic rather than a plain size_t
// purely so the write in InitHeaderPoWCache() and the read in
// GetHeaderPoWCache()'s static-initializer are both well-defined even if
// (contrary to the documented contract) they were ever to race; it is not
// meant to imply this is a supported way to resize the cache at runtime.
static std::atomic<size_t> g_header_pow_cache_bytes{DEFAULT_HEADER_POW_CACHE_BYTES};
// Set the first time GetHeaderPoWCache() actually constructs the cache, so
// InitHeaderPoWCache() can assert it isn't called too late (after which it
// would be a silent, hard-to-notice no-op instead).
static std::atomic<bool> g_header_pow_cache_constructed{false};

void InitHeaderPoWCache(size_t max_size_bytes)
{
    assert(!g_header_pow_cache_constructed.load(std::memory_order_relaxed) &&
           "InitHeaderPoWCache() called after GetHeaderPoWCache() already "
           "constructed the cache -- call it earlier in process startup, "
           "before any header/block processing begins");
    g_header_pow_cache_bytes.store(max_size_bytes, std::memory_order_relaxed);
}

HeaderPoWCache& GetHeaderPoWCache()
{
    // Constructed once, lazily, on first use, and lives for the rest of the
    // process. Initialization of function-local statics is thread-safe
    // since C++11, so no extra locking is needed here.
    //
    // Sized from g_header_pow_cache_bytes, which is either still at its
    // compiled-in default (DEFAULT_HEADER_POW_CACHE_BYTES, ~2.1M headers /
    // 64 MiB -- see pow_cache.h for the full sizing rationale) or was
    // overridden by an earlier InitHeaderPoWCache() call from app-level
    // startup code (bitwebd's -headerpowcachesize=<MiB>; see
    // node/chainstatemanager_args.cpp and init.cpp). Either way, by the
    // time this static initializes, the value is final for the rest of the
    // process.
    static HeaderPoWCache cache{g_header_pow_cache_bytes.load(std::memory_order_relaxed)};
    g_header_pow_cache_constructed.store(true, std::memory_order_relaxed);
    return cache;
}

bool CheckProofOfWorkCached(const CBlockHeader& header, const Consensus::Params& params)
{
    const uint256 hash{header.GetHash()};
    if (GetHeaderPoWCache().Get(hash)) {
        return true;
    }
    if (!CheckProofOfWork(header.GetArgon2idPoWHash(), header.nBits, params)) {
        return false;
    }
    GetHeaderPoWCache().Set(hash);
    return true;
}
