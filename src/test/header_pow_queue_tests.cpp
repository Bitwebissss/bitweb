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
// HasValidProofOfWork() now takes its CCheckQueue<CHeaderPoWCheck> as a
// parameter instead of reaching into a file-static singleton -- the queue is
// owned by ChainstateManager (m_header_pow_check_queue, see validation.h/.cpp),
// same lifetime discipline as m_script_check_queue. RegTestingSetup's
// m_node.chainman is a fresh ChainstateManager per test case, and
// ~ChainTestingSetup() resets it (joining the queue's worker threads via
// ~CCheckQueue()) before the test case returns -- so, unlike the previous
// process-lifetime singleton, nothing here can survive to race with
// util_tests.cpp's test_LockDirectory fork() later in the same process.
// That's why the >= HEADER_POW_PARALLEL_THRESHOLD tests below are safe to
// run through the real HasValidProofOfWork(), passing m_node.chainman's
// queue explicitly.

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
// HasValidProofOfWork()'s public sequential and queue-backed branches,
// exercised through the real function against m_node.chainman's own
// ChainstateManager-owned queue (see file header comment above).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(has_valid_pow_sequential_path_below_threshold)
{
    auto& queue = m_node.chainman->GetHeaderCheckQueue();
    auto headers{MakeValidHeaders(HEADER_POW_PARALLEL_THRESHOLD - 1)};
    BOOST_CHECK(HasValidProofOfWork(headers, m_consensus, queue));
    headers.back() = MakeInvalidHeader(999);
    BOOST_CHECK(!HasValidProofOfWork(headers, m_consensus, queue));
}

BOOST_AUTO_TEST_CASE(has_valid_pow_queue_path_at_and_above_threshold)
{
    auto& queue = m_node.chainman->GetHeaderCheckQueue();

    // Exactly at the threshold: dispatched through the queue, all valid.
    auto headers{MakeValidHeaders(HEADER_POW_PARALLEL_THRESHOLD)};
    BOOST_CHECK(HasValidProofOfWork(headers, m_consensus, queue));

    // A large batch, well above the threshold, with an invalid header
    // somewhere in the middle -- must still be caught via the queue path.
    auto big_headers{MakeValidHeaders(257, /*base=*/10'000)};
    big_headers[130] = MakeInvalidHeader(4242);
    BOOST_CHECK(!HasValidProofOfWork(big_headers, m_consensus, queue));
}

BOOST_AUTO_TEST_CASE(has_valid_pow_queue_reusable_across_calls)
{
    // The same ChainstateManager-owned queue must be safe to reuse across
    // repeated HasValidProofOfWork() calls, mixing valid and invalid
    // batches, the way real header-sync batches would.
    auto& queue = m_node.chainman->GetHeaderCheckQueue();

    for (int round = 0; round < 5; ++round) {
        auto headers{MakeValidHeaders(HEADER_POW_PARALLEL_THRESHOLD + 10, /*base=*/static_cast<uint32_t>(round * 1000))};
        BOOST_CHECK(HasValidProofOfWork(headers, m_consensus, queue));

        headers[5] = MakeInvalidHeader(static_cast<uint32_t>(round));
        BOOST_CHECK(!HasValidProofOfWork(headers, m_consensus, queue));
    }
}

BOOST_AUTO_TEST_SUITE_END()
