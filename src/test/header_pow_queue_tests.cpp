// Copyright (c) 2026-present The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Scope of this file: CHeaderPoWCheck's CCheckQueue plumbing and
// HasValidProofOfWork()'s sequential/parallel dispatch (validation.h/.cpp).
//
// Deliberately OUT of scope here (covered elsewhere, not re-tested):
//   - Argon2id PoW correctness itself         -> crypto_argon2id_tests.cpp
//   - CheckProofOfWork()/target math (compact
//     encoding, negative/overflow/zero target) -> pow_tests.cpp
//   - HeaderPoWCache hit/miss/eviction         -> pow_cache.h/.cpp (own tests, if any)
//   - HeadersSyncState chainwork/commitments   -> headers_sync_chainwork_tests.cpp
//
// Every header built below is either "guaranteed valid" (regtest powLimit +
// nonce search, same trick as headers_sync_chainwork_tests.cpp) or
// "guaranteed invalid" (negative-target nBits, same trick as pow_tests.cpp's
// CheckProofOfWork_test_negative_target). Neither depends on genuinely
// exercising Argon2id correctness -- they're only the vehicle to get a
// deterministic true/false result flowing through the queue and through
// HasValidProofOfWork()'s threshold branch.
//
// IMPORTANT: this file deliberately never calls the real HasValidProofOfWork()
// with headers.size() >= HEADER_POW_PARALLEL_THRESHOLD. That path lazily
// constructs validation.cpp's file-static GetHeaderPoWCheckQueue() singleton,
// which by design (see its comment in validation.cpp) is constructed once and
// lives for the rest of the process -- its worker threads are only ever
// joined at process exit, not at the end of a test case. In this test binary
// that is unsafe: util_tests.cpp's test_LockDirectory calls fork() later in
// the same process, and POSIX fork() only carries the calling thread into the
// child -- any other thread that happens to be mid-way through a libc/libstdc++
// lock (malloc arena, iostream, TLS/dlopen, ...) at the instant of fork()
// leaves that lock permanently "held" in the child, which can hang or corrupt
// state the next time the child needs it. Every other test in this file (and
// in checkqueue_tests.cpp) only ever builds short-lived, function-scoped
// CCheckQueue objects whose worker threads are joined by ~CCheckQueue() before
// the test case returns, so nothing survives to race with a later fork(). The
// real singleton is therefore only exercised below the threshold, where
// HasValidProofOfWork() never touches GetHeaderPoWCheckQueue() at all.

#include <algorithm>
#include <arith_uint256.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>

#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

struct HeaderPoWCheckQueueTest : RegTestingSetup {
    const Consensus::Params& m_consensus{Params().GetConsensus()};

    const uint32_t m_always_invalid_nbits{UintToArith256(m_consensus.powLimit).GetCompact(/*fNegative=*/true)};

    CBlockHeader MakeValidHeader(uint32_t distinguisher) const
    {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock = uint256::ZERO;
        header.hashMerkleRoot = uint256::ZERO;
        header.nTime = 1'700'000'000 + distinguisher;
        header.nBits = Params().GenesisBlock().nBits;
        header.nNonce = 0;
        while (!CheckProofOfWork(header.GetArgon2idPoWHash(), header.nBits, m_consensus)) {
            ++header.nNonce;
        }
        return header;
    }

    CBlockHeader MakeInvalidHeader(uint32_t distinguisher) const
    {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock = uint256::ZERO;
        header.hashMerkleRoot = uint256::ZERO;
        header.nTime = 1'800'000'000 + distinguisher;
        header.nBits = m_always_invalid_nbits;
        header.nNonce = 0;
        return header;
    }

    std::vector<CBlockHeader> MakeValidHeaders(size_t count, uint32_t base = 0) const
    {
        std::vector<CBlockHeader> headers;
        headers.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            headers.push_back(MakeValidHeader(base + static_cast<uint32_t>(i)));
        }
        return headers;
    }

    std::vector<CHeaderPoWCheck> MakeChecks(const std::vector<CBlockHeader>& headers) const
    {
        std::vector<CHeaderPoWCheck> checks;
        checks.reserve(headers.size());
        for (const auto& header : headers) {
            checks.emplace_back(header, m_consensus);
        }
        return checks;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(header_pow_queue_tests, HeaderPoWCheckQueueTest)

BOOST_AUTO_TEST_CASE(local_queue_no_losses_all_valid)
{
    CCheckQueue<CHeaderPoWCheck> queue{/*batch_size=*/64, /*worker_threads_num=*/3};

    for (const size_t count : {size_t{0}, size_t{1}, size_t{2}, size_t{31}, size_t{32}, size_t{33}, size_t{64}, size_t{257}}) {
        const auto headers{MakeValidHeaders(count, /*base=*/static_cast<uint32_t>(count * 1000))};

        CCheckQueueControl<CHeaderPoWCheck> control(queue);
        size_t added = 0;
        while (added < headers.size()) {
            const size_t batch = std::min(headers.size() - added, size_t{1} + m_rng.randrange(9));
            std::vector<CHeaderPoWCheck> vAdd;
            vAdd.reserve(batch);
            for (size_t i = 0; i < batch; ++i) {
                vAdd.emplace_back(headers[added + i], m_consensus);
            }
            control.Add(std::move(vAdd));
            added += batch;
        }
        BOOST_REQUIRE(!control.Complete().has_value());
    }
}

BOOST_AUTO_TEST_CASE(local_queue_detects_invalid_header_anywhere)
{
    CCheckQueue<CHeaderPoWCheck> queue{/*batch_size=*/64, /*worker_threads_num=*/3};
    constexpr size_t kBatch = 200;

    for (const size_t bad_pos : {size_t{0}, size_t{1}, kBatch / 2, kBatch - 2, kBatch - 1}) {
        auto headers{MakeValidHeaders(kBatch, /*base=*/static_cast<uint32_t>(bad_pos * 10000))};
        headers[bad_pos] = MakeInvalidHeader(static_cast<uint32_t>(bad_pos));

        CCheckQueueControl<CHeaderPoWCheck> control(queue);
        size_t added = 0;
        while (added < headers.size()) {
            const size_t batch = std::min(headers.size() - added, size_t{1} + m_rng.randrange(9));
            std::vector<CHeaderPoWCheck> vAdd;
            vAdd.reserve(batch);
            for (size_t i = 0; i < batch; ++i) {
                vAdd.emplace_back(headers[added + i], m_consensus);
            }
            control.Add(std::move(vAdd));
            added += batch;
        }
        BOOST_REQUIRE(control.Complete().has_value());
    }
}

BOOST_AUTO_TEST_CASE(local_queue_recovers_between_batches)
{
    CCheckQueue<CHeaderPoWCheck> queue{/*batch_size=*/64, /*worker_threads_num=*/3};

    for (int round = 0; round < 10; ++round) {
        for (const bool inject_failure : {true, false}) {
            auto headers{MakeValidHeaders(50, /*base=*/static_cast<uint32_t>(round * 100))};
            if (inject_failure) {
                headers[25] = MakeInvalidHeader(static_cast<uint32_t>(round));
            }

            CCheckQueueControl<CHeaderPoWCheck> control(queue);
            control.Add(MakeChecks(headers));
            const bool failed = control.Complete().has_value();
            BOOST_REQUIRE_EQUAL(failed, inject_failure);
        }
    }
}

BOOST_AUTO_TEST_CASE(concurrent_controls_do_not_cross_contaminate)
{
    CCheckQueue<CHeaderPoWCheck> queue{/*batch_size=*/64, /*worker_threads_num=*/3};
    constexpr int kThreads = 6;

    std::vector<std::thread> threads;
    std::vector<int> observed(kThreads, -1);
    std::vector<int> expected(kThreads, -1);

    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        expected[t] = (t % 2 == 0) ? 1 : 0;
        threads.emplace_back([&, t] {
            auto headers{MakeValidHeaders(80, /*base=*/static_cast<uint32_t>(t * 1000))};
            if (expected[t] == 1) {
                headers[40] = MakeInvalidHeader(static_cast<uint32_t>(t));
            }

            CCheckQueueControl<CHeaderPoWCheck> control(queue);
            control.Add(MakeChecks(headers));
            observed[t] = control.Complete().has_value() ? 1 : 0;
        });
    }
    for (auto& th : threads) th.join();

    for (int t = 0; t < kThreads; ++t) {
        BOOST_CHECK_EQUAL(observed[t], expected[t]);
    }
}

// ---------------------------------------------------------------------------
// HasValidProofOfWork()'s sequential branch, exercised through the real
// public function. Deliberately capped below HEADER_POW_PARALLEL_THRESHOLD:
// that branch returns via CheckProofOfWorkCached() without ever calling
// GetHeaderPoWCheckQueue(), so it cannot leak the process-lifetime singleton
// thread pool described in the file header comment above. Coverage of the
// >= threshold, queue-backed branch's *mechanics* (batching, loss-free
// dispatch, failure aggregation, concurrent CCheckQueueControl use) is
// already exhaustive via local_queue_* and concurrent_controls_* above,
// against a queue built the same way GetHeaderPoWCheckQueue() builds its own.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(has_valid_pow_sequential_path_below_threshold)
{
    auto headers{MakeValidHeaders(HEADER_POW_PARALLEL_THRESHOLD - 1)};
    BOOST_CHECK(HasValidProofOfWork(headers, m_consensus));
    headers.back() = MakeInvalidHeader(999);
    BOOST_CHECK(!HasValidProofOfWork(headers, m_consensus));
}

BOOST_AUTO_TEST_SUITE_END()
