#pragma once

#include "ProtocolDecoder.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace tpi {

struct TalkerStat {
    std::string address;
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
};

/// Modbus-specific counters, including request/response latency matched by transaction.
struct ModbusStats {
    std::uint64_t requests = 0;
    std::uint64_t responses = 0;
    std::uint64_t exceptions = 0;
    std::array<std::uint64_t, 128> functionCounts{};
    std::uint64_t matchedTransactions = 0;
    double latencySumMs = 0.0;
    double latencyMaxMs = 0.0;
    double lastLatencyMs = 0.0;
    std::string lastException;

    [[nodiscard]] std::uint64_t total() const noexcept { return requests + responses; }
    [[nodiscard]] double averageLatencyMs() const noexcept {
        return matchedTransactions == 0 ? 0.0 : latencySumMs / static_cast<double>(matchedTransactions);
    }
};

/// Aggregates decoded packets into the numbers shown on the dashboard.
///
/// Rates are sampled in fixed buckets on the *processing* clock (steady_clock), so a pcap
/// file read at full speed and a live capture both produce a meaningful throughput graph.
/// All internal containers are bounded, so memory stays flat during long captures.
class TrafficStats {
public:
    using SteadyClock = std::chrono::steady_clock;

    explicit TrafficStats(std::chrono::milliseconds sampleInterval = std::chrono::milliseconds(500),
                          std::size_t historyLength = 240);

    void record(const DecodedPacket& packet);
    /// Closes every sample bucket that ended before `now`.
    void advance(SteadyClock::time_point now);
    void reset();

    [[nodiscard]] std::uint64_t totalPackets() const noexcept { return totalPackets_; }
    [[nodiscard]] std::uint64_t totalBytes() const noexcept { return totalBytes_; }
    [[nodiscard]] std::uint64_t malformedPackets() const noexcept { return malformed_; }
    [[nodiscard]] std::uint64_t protocolCount(Protocol protocol) const noexcept {
        return protocolCounts_[static_cast<std::size_t>(protocol)];
    }
    [[nodiscard]] std::uint64_t tcpResets() const noexcept { return tcpResets_; }
    [[nodiscard]] std::uint64_t tcpSyns() const noexcept { return tcpSyns_; }

    [[nodiscard]] const std::deque<double>& packetRateHistory() const noexcept { return packetRates_; }
    [[nodiscard]] const std::deque<double>& byteRateHistory() const noexcept { return byteRates_; }
    [[nodiscard]] double packetRate() const noexcept { return packetRates_.empty() ? 0.0 : packetRates_.back(); }
    [[nodiscard]] double byteRate() const noexcept { return byteRates_.empty() ? 0.0 : byteRates_.back(); }
    [[nodiscard]] double peakPacketRate() const noexcept { return peakPacketRate_; }
    [[nodiscard]] std::chrono::milliseconds sampleInterval() const noexcept { return sampleInterval_; }

    [[nodiscard]] std::vector<TalkerStat> topTalkers(std::size_t limit) const;
    [[nodiscard]] const ModbusStats& modbus() const noexcept { return modbus_; }

private:
    void recordModbus(const DecodedPacket& packet);

    static constexpr std::size_t kMaxTalkers = 4096;
    static constexpr std::size_t kMaxPendingTransactions = 4096;

    std::chrono::milliseconds sampleInterval_;
    std::size_t historyLength_;

    std::uint64_t totalPackets_ = 0;
    std::uint64_t totalBytes_ = 0;
    std::uint64_t malformed_ = 0;
    std::uint64_t tcpResets_ = 0;
    std::uint64_t tcpSyns_ = 0;
    std::array<std::uint64_t, 8> protocolCounts_{};

    SteadyClock::time_point bucketStart_;
    std::uint64_t bucketPackets_ = 0;
    std::uint64_t bucketBytes_ = 0;
    std::deque<double> packetRates_;
    std::deque<double> byteRates_;
    double peakPacketRate_ = 0.0;

    std::unordered_map<std::string, TalkerStat> talkers_;
    std::unordered_map<std::string, Clock::time_point> pendingTransactions_;
    ModbusStats modbus_;
};

}  // namespace tpi
