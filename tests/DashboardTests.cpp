#include "NetworkSniffer.hpp"
#include "ProtocolDecoder.hpp"
#include "TestFramework.hpp"
#include "TrafficStats.hpp"
#include "TuiRenderer.hpp"

#include <string>
#include <vector>

using namespace tpi;

namespace {

DecodedPacket modbusPacket(ModbusDirection direction, std::uint16_t tid, Clock::time_point when, bool exception = false) {
    DecodedPacket packet;
    packet.timestamp = when;
    packet.wireLength = 66;
    packet.protocol = Protocol::Modbus;
    IpHeader ip;
    ip.version = 4;
    ip.source.version = 4;
    ip.destination.version = 4;
    ip.source.bytes = {192, 168, 1, direction == ModbusDirection::Request ? std::uint8_t{50} : std::uint8_t{10}};
    ip.destination.bytes = {192, 168, 1, direction == ModbusDirection::Request ? std::uint8_t{10} : std::uint8_t{50}};
    packet.ip = ip;
    TcpHeader tcp;
    tcp.sourcePort = direction == ModbusDirection::Request ? 49712 : 502;
    tcp.destinationPort = direction == ModbusDirection::Request ? 502 : 49712;
    packet.tcp = tcp;
    ModbusFrame frame;
    frame.direction = direction;
    frame.transactionId = tid;
    frame.functionCode = 3;
    frame.isException = exception;
    frame.exceptionCode = exception ? 2 : 0;
    packet.modbus = frame;
    return packet;
}

/// Decodes a few seconds of the deterministic demo stream.
std::vector<DecodedPacket> demoTraffic(std::size_t count) {
    SyntheticOptions options;
    options.packetsPerSecond = 50000;
    options.seed = 7;
    auto source = openSyntheticSource(options);
    const ProtocolDecoder decoder;
    std::vector<DecodedPacket> packets;
    RawPacket raw;
    while (packets.size() < count) {
        if (source->read(raw, std::chrono::milliseconds(50)) == ReadStatus::Packet) {
            packets.push_back(decoder.decode(raw));
        }
    }
    return packets;
}

}  // namespace

TPI_TEST(stats_samples_rates_per_bucket) {
    TrafficStats stats(std::chrono::milliseconds(100), 16);
    const auto start = TrafficStats::SteadyClock::now();
    DecodedPacket packet;
    packet.wireLength = 100;
    packet.protocol = Protocol::Udp;
    for (int i = 0; i < 10; ++i) {
        stats.record(packet);
    }
    stats.advance(start + std::chrono::milliseconds(150));
    CHECK_EQ(stats.packetRateHistory().size(), 1u);
    CHECK(stats.packetRate() > 99.0 && stats.packetRate() < 101.0);  // 10 packets / 0.1 s
    CHECK(stats.byteRate() > 9999.0 && stats.byteRate() < 10001.0);
    CHECK_EQ(stats.protocolCount(Protocol::Udp), 10u);
    stats.advance(start + std::chrono::seconds(10));
    CHECK(stats.packetRateHistory().size() <= 16u);  // history is bounded
}

TPI_TEST(stats_match_modbus_request_response_latency) {
    TrafficStats stats;
    const auto t0 = Clock::now();
    stats.record(modbusPacket(ModbusDirection::Request, 7, t0));
    stats.record(modbusPacket(ModbusDirection::Response, 7, t0 + std::chrono::milliseconds(12)));
    stats.record(modbusPacket(ModbusDirection::Request, 8, t0));
    stats.record(modbusPacket(ModbusDirection::Response, 8, t0 + std::chrono::milliseconds(4), true));
    const ModbusStats& modbus = stats.modbus();
    CHECK_EQ(modbus.requests, 2u);
    CHECK_EQ(modbus.responses, 2u);
    CHECK_EQ(modbus.exceptions, 1u);
    CHECK_EQ(modbus.matchedTransactions, 2u);
    CHECK(modbus.averageLatencyMs() > 7.9 && modbus.averageLatencyMs() < 8.1);
    CHECK(modbus.latencyMaxMs > 11.9 && modbus.latencyMaxMs < 12.1);
    CHECK(modbus.lastException.find("Illegal Data Address") != std::string::npos);
}

TPI_TEST(stats_top_talkers_sorted_by_bytes) {
    TrafficStats stats;
    for (const auto& packet : demoTraffic(500)) {
        stats.record(packet);
    }
    const auto talkers = stats.topTalkers(5);
    CHECK(!talkers.empty());
    for (std::size_t i = 1; i < talkers.size(); ++i) {
        CHECK(talkers[i - 1].bytes >= talkers[i].bytes);
    }
    CHECK(stats.protocolCount(Protocol::Modbus) > 0);
}

TPI_TEST(log_filter_cycles_through_all_modes) {
    LogFilter filter = LogFilter::All;
    for (int i = 0; i < 5; ++i) {
        filter = nextLogFilter(filter);
    }
    CHECK(filter == LogFilter::All);
    LogEntry entry;
    entry.protocol = Protocol::Arp;
    CHECK(logFilterMatches(LogFilter::Other, entry));
    CHECK(!logFilterMatches(LogFilter::Tcp, entry));
}

TPI_TEST(render_frame_contains_all_panels) {
    TrafficStats stats(std::chrono::milliseconds(50), 64);
    std::deque<LogEntry> log;
    std::uint64_t number = 0;
    auto now = TrafficStats::SteadyClock::now();
    for (const auto& packet : demoTraffic(400)) {
        stats.record(packet);
        log.push_back(makeLogEntry(++number, packet));
        now += std::chrono::milliseconds(5);
        stats.advance(now);
    }
    DashboardState state;
    state.sourceDescription = "unit-test";
    for (const bool unicode : {true, false}) {
        for (const bool color : {true, false}) {
            const std::string frame = TuiRenderer::renderFrame(stats, log, state, {120, 40}, {color, unicode});
            CHECK(frame.find("Throughput") != std::string::npos);
            CHECK(frame.find("Protocols") != std::string::npos);
            CHECK(frame.find("Top talkers") != std::string::npos);
            CHECK(frame.find("Modbus / ICS") != std::string::npos);
            CHECK(frame.find("Packet log") != std::string::npos);
            CHECK(frame.find("unit-test") != std::string::npos);
        }
    }
}

TPI_TEST(render_frame_survives_extreme_sizes) {
    const TrafficStats stats;
    const std::deque<LogEntry> log;
    DashboardState state;
    state.showHelp = true;
    state.scrollOffset = 999;
    const TerminalSize sizes[] = {{1, 1}, {20, 5}, {79, 21}, {80, 22}, {300, 120}};
    for (const TerminalSize& size : sizes) {
        const std::string frame = TuiRenderer::renderFrame(stats, log, state, size, {});
        CHECK(!frame.empty());
    }
    const std::string tiny = TuiRenderer::renderFrame(stats, log, state, {40, 10}, {});
    CHECK(tiny.find("too small") != std::string::npos);
}
