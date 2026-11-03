// Portable same-host benchmark for the LWR kernel used by PQDiSE-from-PQDPRF.
//
// This benchmark intentionally depends only on NTL. It reproduces the arithmetic
// in pqdise/dEnc_tests/Compare_DPrfs.cpp at upstream commit
// e520c669c16160d802c0d86b3034310750277899, while excluding cryptoTools,
// input expansion, serialization, signatures, and networking from the timed region.

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using Nanoseconds = std::chrono::nanoseconds;
using u64 = std::uint64_t;

constexpr int kDimension = 1024;
constexpr int kLogQ = 64;
constexpr int kLogQ1 = 42;
constexpr int kLogP = 10;
constexpr int kAuthorities = 7;
constexpr int kSamplesPerConfiguration = 1000;
constexpr int kBlocks = 10;
constexpr int kSamplesPerBlock =
    kSamplesPerConfiguration / kBlocks;
constexpr int kWarmupSamples = 20;
constexpr u64 kSeed = 20260820;
constexpr const char* kReferenceCommit =
    "e520c669c16160d802c0d86b3034310750277899";

static_assert(sizeof(unsigned long) == sizeof(u64),
              "the reference conversion requires a 64-bit unsigned long");

u64 elapsed_ns(Clock::time_point start, Clock::time_point end) {
    return static_cast<u64>(
        std::chrono::duration_cast<Nanoseconds>(end - start).count());
}

u64 rounded_power_of_two(u64 value, int source_bits, int target_bits) {
    value >>= source_bits - target_bits - 1;
    const u64 round_up = value & 1U;
    value >>= 1;
    return value + round_up;
}

u64 residue_u64(const NTL::ZZ_p& value) {
    return static_cast<u64>(NTL::conv<unsigned long>(NTL::rep(value)));
}

struct Configuration {
    int output_components;
    int threshold;
};

struct Measurement {
    u64 share_setup_ns;
    std::vector<u64> partial_ns;
    u64 partial_sequential_ns;
    u64 partial_max_ns;
    u64 combine_ns;
    u64 sequential_total_ns;
    u64 parallel_model_ns;
    int mismatched_components;
    u64 checksum;
};

Measurement measure_once(const Configuration& configuration) {
    NTL::vec_ZZ_p key;
    key.SetLength(kDimension);
    NTL::random(key, kDimension);

    std::vector<NTL::vec_ZZ_p> inputs(configuration.output_components);
    for (auto& input : inputs) {
        input.SetLength(kDimension);
        NTL::random(input, kDimension);
    }

    std::vector<NTL::vec_ZZ_p> shares(configuration.threshold);
    for (auto& share : shares) {
        share.SetLength(kDimension);
    }

    const auto setup_start = Clock::now();
    NTL::VectorCopy(shares[0], key, kDimension);
    for (int party = 1; party < configuration.threshold; ++party) {
        NTL::random(shares[party], kDimension);
        shares[0] += shares[party];
    }
    const auto setup_end = Clock::now();

    std::vector<std::vector<u64>> partials(
        configuration.threshold,
        std::vector<u64>(configuration.output_components));
    std::vector<u64> partial_ns(configuration.threshold);

    const auto total_start = Clock::now();
    for (int party = 0; party < configuration.threshold; ++party) {
        const auto partial_start = Clock::now();
        for (int component = 0;
             component < configuration.output_components;
             ++component) {
            NTL::ZZ_p inner_product;
            NTL::InnerProduct(inner_product, inputs[component], shares[party]);
            partials[party][component] = rounded_power_of_two(
                residue_u64(inner_product), kLogQ, kLogQ1);
        }
        const auto partial_end = Clock::now();
        partial_ns[party] = elapsed_ns(partial_start, partial_end);
    }

    const u64 q1_mask = (u64{1} << kLogQ1) - 1;
    std::vector<u64> combined(configuration.output_components);
    const auto combine_start = Clock::now();
    for (int component = 0;
         component < configuration.output_components;
         ++component) {
        u64 value = partials[0][component];
        for (int party = 1; party < configuration.threshold; ++party) {
            value = (value - partials[party][component]) & q1_mask;
        }
        combined[component] =
            rounded_power_of_two(value, kLogQ1, kLogP);
    }
    const auto combine_end = Clock::now();
    const auto total_end = combine_end;

    int mismatches = 0;
    u64 checksum = 0;
    for (int component = 0;
         component < configuration.output_components;
         ++component) {
        NTL::ZZ_p direct_inner_product;
        NTL::InnerProduct(direct_inner_product, inputs[component], key);
        const u64 direct = rounded_power_of_two(
            residue_u64(direct_inner_product), kLogQ, kLogP);
        mismatches += direct != combined[component];
        checksum = (checksum * 1315423911U) ^ combined[component];
    }

    const u64 partial_sequential =
        std::accumulate(partial_ns.begin(), partial_ns.end(), u64{0});
    const u64 partial_max =
        *std::max_element(partial_ns.begin(), partial_ns.end());
    const u64 combine = elapsed_ns(combine_start, combine_end);

    return Measurement{
        elapsed_ns(setup_start, setup_end),
        std::move(partial_ns),
        partial_sequential,
        partial_max,
        combine,
        elapsed_ns(total_start, total_end),
        partial_max + combine,
        mismatches,
        checksum,
    };
}

void emit_record(const Configuration& configuration,
                 int block,
                 int run,
                 const Measurement& measurement) {
    std::cout
        << "{\"schema\":\"astra-pq-pqdprf-same-host-v1\""
        << ",\"reference_commit\":\"" << kReferenceCommit << "\""
        << ",\"reference_kernel\":\"portable-ntl-reproduction\""
        << ",\"timed_scope\":\"lwr-partial-and-final-evaluation-only\""
        << ",\"input_expansion_timed\":false"
        << ",\"network_timed\":false"
        << ",\"dimension\":" << kDimension
        << ",\"log_q\":" << kLogQ
        << ",\"log_q1\":" << kLogQ1
        << ",\"log_p\":" << kLogP
        << ",\"configured_authorities\":" << kAuthorities
        << ",\"threshold\":" << configuration.threshold
        << ",\"output_components\":" << configuration.output_components
        << ",\"nominal_output_bits\":"
        << configuration.output_components * kLogP
        << ",\"block\":" << block
        << ",\"run\":" << run
        << ",\"share_setup_ns\":" << measurement.share_setup_ns
        << ",\"partial_evaluation_ns\":[";

    for (std::size_t index = 0; index < measurement.partial_ns.size(); ++index) {
        if (index != 0) {
            std::cout << ',';
        }
        std::cout << measurement.partial_ns[index];
    }

    std::cout
        << "]"
        << ",\"partial_evaluations_sequential_ns\":"
        << measurement.partial_sequential_ns
        << ",\"slowest_partial_evaluation_ns\":"
        << measurement.partial_max_ns
        << ",\"final_combination_ns\":" << measurement.combine_ns
        << ",\"sequential_total_ns\":" << measurement.sequential_total_ns
        << ",\"parallel_computation_model_ns\":"
        << measurement.parallel_model_ns
        << ",\"mismatched_components\":"
        << measurement.mismatched_components
        << ",\"checksum\":" << measurement.checksum
        << ",\"raw_share_bytes_per_authority\":"
        << kDimension * static_cast<int>(sizeof(u64))
        << ",\"partial_payload_bytes_per_authority\":"
        << configuration.output_components * static_cast<int>(sizeof(u64))
        << "}\n";
}

}  // namespace

int main() {
    NTL::SetSeed(NTL::conv<NTL::ZZ>(kSeed));
    NTL::ZZ_p::init(NTL::power2_ZZ(kLogQ));

    std::vector<Configuration> configurations;
    for (const int components : {13, 26}) {
        for (int threshold = 1; threshold <= kAuthorities; ++threshold) {
            configurations.push_back(Configuration{components, threshold});
        }
    }

    for (const auto& configuration : configurations) {
        for (int warmup = 0; warmup < kWarmupSamples; ++warmup) {
            static_cast<void>(measure_once(configuration));
        }
    }

    for (int block = 0; block < kBlocks; ++block) {
        for (std::size_t offset = 0; offset < configurations.size(); ++offset) {
            const auto& configuration = configurations[
                (offset + static_cast<std::size_t>(block)) % configurations.size()];
            for (int within_block = 0;
                 within_block < kSamplesPerBlock;
                 ++within_block) {
                const int run = block * kSamplesPerBlock + within_block + 1;
                emit_record(configuration, block + 1, run,
                            measure_once(configuration));
            }
        }
    }

    return EXIT_SUCCESS;
}
