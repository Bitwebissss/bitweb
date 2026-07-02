// Copyright (c) 2026-present The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow_cache.h>

#include <pow.h>
#include <primitives/block.h>

HeaderPoWCache& GetHeaderPoWCache()
{
    // Constructed once, lazily, on first use, and lives for the rest of the
    // process. Initialization of function-local statics is thread-safe
    // since C++11, so no extra locking is needed here.
    //
    // Sized for ~2.1M headers (2,097,152 = 2^21 entries, exactly 64 MiB at
    // sizeof(uint256)=32 bytes/entry). At a 5-minute block spacing this
    // covers roughly 20 years of chain height before a fresh-IBD node's
    // header-validation cache writes would start getting evicted ahead of
    // the corresponding block-body downloads catching up. Current chain
    // height is ~220k, so this is a deliberately generous, hardcoded
    // constant rather than a config option for now -- revisit as a
    // -args-tunable parameter (mirroring SignatureCache's
    // -maxsigcachesize pattern) if/when that becomes worth the
    // complexity. 64 MiB is negligible next to typical -dbcache budgets.
    static HeaderPoWCache cache;
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
