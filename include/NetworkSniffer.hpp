#pragma once

#include "Packet.hpp"
#include "PacketBuffer.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

namespace tpi {

/// Thrown when a capture source cannot be opened or fails irrecoverably.
class CaptureError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class ReadStatus : std::uint8_t {
    Packet,      ///< `out` was filled with a new packet.
    Timeout,     ///< Nothing arrived within the timeout; try again.
    EndOfStream  ///< The source is exhausted (e.g. end of a pcap file).
};

/// Abstract producer of raw packets: a live socket, a pcap file or a virtual stream.
class CaptureSource {
public:
    CaptureSource() = default;
    CaptureSource(const CaptureSource&) = delete;
    CaptureSource& operator=(const CaptureSource&) = delete;
    virtual ~CaptureSource() = default;

    /// Waits at most `timeout` for the next packet.
    virtual ReadStatus read(RawPacket& out, std::chrono::milliseconds timeout) = 0;

    /// Human readable description shown in the UI, e.g. "live:eth0".
    [[nodiscard]] virtual std::string description() const = 0;
};

/// Options for the built-in virtual traffic generator.
struct SyntheticOptions {
    double packetsPerSecond = 300.0;  ///< Average rate; the generator adds waves and bursts.
    std::uint16_t modbusPort = 502;   ///< Port used for generated Modbus/TCP traffic.
    std::uint32_t seed = 0;           ///< 0 = random seed, anything else = reproducible stream.
};

/// Opens a live capture.
///  - Linux:   AF_PACKET raw socket; `interfaceName` is e.g. "eth0" (empty = all interfaces).
///  - Windows: raw IP socket with SIO_RCVALL; `interfaceName` is a local IPv4 address
///             (empty = first non-loopback address).
/// Requires elevated privileges (root / CAP_NET_RAW / Administrator).
std::unique_ptr<CaptureSource> openLiveSource(const std::string& interfaceName);

/// Opens a classic libpcap file (.pcap, micro- or nanosecond, either byte order).
/// With `realtime` set, packets are replayed honoring their original inter-arrival gaps.
std::unique_ptr<CaptureSource> openPcapFile(const std::string& path, bool realtime);

/// Opens a virtual stream that synthesizes realistic Ethernet / IPv4 / IPv6 / TCP / UDP /
/// ARP / ICMP / Modbus traffic. Needs no privileges - perfect for demos and development.
std::unique_ptr<CaptureSource> openSyntheticSource(const SyntheticOptions& options);

/// Writes captured packets to a classic libpcap file readable by Wireshark / tcpdump.
/// The file header is emitted lazily, using the link type of the first packet.
class PcapWriter {
public:
    explicit PcapWriter(const std::string& path);

    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    /// Returns false when the packet could not be written (I/O error or link type mismatch).
    bool write(const RawPacket& packet);

    [[nodiscard]] std::uint64_t packetsWritten() const noexcept { return written_; }

private:
    void writeHeader(LinkType linkType);

    std::ofstream stream_;
    bool headerWritten_ = false;
    LinkType linkType_ = LinkType::Ethernet;
    std::uint64_t written_ = 0;
};

/// Capture engine: owns a CaptureSource and pumps its packets into a PacketBuffer on a
/// dedicated background thread. The thread is joined automatically on destruction (RAII).
class NetworkSniffer {
public:
    NetworkSniffer(std::unique_ptr<CaptureSource> source, PacketBuffer& buffer);
    ~NetworkSniffer();

    NetworkSniffer(const NetworkSniffer&) = delete;
    NetworkSniffer& operator=(const NetworkSniffer&) = delete;
    NetworkSniffer(NetworkSniffer&&) = delete;
    NetworkSniffer& operator=(NetworkSniffer&&) = delete;

    /// Optionally mirrors every captured packet into a pcap file. Call before start().
    void setRecorder(std::unique_ptr<PcapWriter> recorder);

    void start();
    void stop();

    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    /// True once the source reported end of stream or failed.
    [[nodiscard]] bool finished() const noexcept { return finished_.load(); }
    [[nodiscard]] std::uint64_t capturedPackets() const noexcept { return packets_.load(); }
    [[nodiscard]] std::uint64_t capturedBytes() const noexcept { return bytes_.load(); }
    [[nodiscard]] std::string description() const { return description_; }
    /// Last fatal error raised by the source, empty if none.
    [[nodiscard]] std::string lastError() const;

private:
    void run();

    std::unique_ptr<CaptureSource> source_;
    std::unique_ptr<PcapWriter> recorder_;
    PacketBuffer& buffer_;
    std::string description_;

    std::atomic<bool> stopRequested_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> finished_{false};
    std::atomic<std::uint64_t> packets_{0};
    std::atomic<std::uint64_t> bytes_{0};

    mutable std::mutex errorMutex_;
    std::string lastError_;

    std::thread worker_;  // declared last: every member it touches outlives it
};

}  // namespace tpi
