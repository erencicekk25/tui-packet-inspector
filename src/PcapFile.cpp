// Reader and writer for the classic libpcap file format.
// Format reference: https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html

#include "NetworkSniffer.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <thread>
#include <vector>

namespace tpi {
namespace {

constexpr std::uint32_t kMagicMicroseconds = 0xA1B2C3D4;
constexpr std::uint32_t kMagicNanoseconds = 0xA1B23C4D;
constexpr std::uint32_t kLinkTypeEthernet = 1;
constexpr std::uint32_t kLinkTypeRaw = 101;
constexpr std::uint32_t kLinkTypeIpv4 = 228;
constexpr std::uint32_t kLinkTypeIpv6 = 229;
constexpr std::uint32_t kMaxRecordLength = 262144;
constexpr std::size_t kFileHeaderSize = 24;
constexpr std::size_t kRecordHeaderSize = 16;

constexpr std::uint32_t byteSwap32(std::uint32_t v) noexcept {
    return (v >> 24) | ((v >> 8) & 0x0000FF00u) | ((v << 8) & 0x00FF0000u) | (v << 24);
}

std::uint32_t loadNative32(const std::uint8_t* data) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, data, sizeof value);
    return value;
}

void storeNative32(std::uint8_t* data, std::uint32_t value) noexcept { std::memcpy(data, &value, sizeof value); }

void storeNative16(std::uint8_t* data, std::uint16_t value) noexcept { std::memcpy(data, &value, sizeof value); }

class PcapFileSource final : public CaptureSource {
public:
    PcapFileSource(const std::string& path, bool realtime)
        : path_(path), realtime_(realtime), stream_(path, std::ios::binary) {
        if (!stream_) {
            throw CaptureError("cannot open pcap file: " + path);
        }
        std::array<std::uint8_t, kFileHeaderSize> header{};
        if (!stream_.read(reinterpret_cast<char*>(header.data()), header.size())) {
            throw CaptureError("not a pcap file (header too short): " + path);
        }

        const std::uint32_t magic = loadNative32(header.data());
        if (magic == kMagicMicroseconds || magic == kMagicNanoseconds) {
            swapped_ = false;
            nanosecond_ = magic == kMagicNanoseconds;
        } else if (byteSwap32(magic) == kMagicMicroseconds || byteSwap32(magic) == kMagicNanoseconds) {
            swapped_ = true;
            nanosecond_ = byteSwap32(magic) == kMagicNanoseconds;
        } else {
            throw CaptureError("unsupported capture format (pcapng is not supported yet): " + path);
        }

        const std::uint32_t linkType = field(header.data() + 20) & 0x0FFFFFFFu;
        switch (linkType) {
            case kLinkTypeEthernet:
                linkType_ = LinkType::Ethernet;
                break;
            case kLinkTypeRaw:
            case kLinkTypeIpv4:
            case kLinkTypeIpv6:
                linkType_ = LinkType::RawIp;
                break;
            default:
                throw CaptureError("unsupported pcap link type " + std::to_string(linkType) + " in " + path);
        }
    }

    ReadStatus read(RawPacket& out, std::chrono::milliseconds timeout) override {
        if (!pending_) {
            pending_ = readRecord();
            if (!pending_) {
                return ReadStatus::EndOfStream;
            }
        }

        if (realtime_) {
            const auto now = std::chrono::steady_clock::now();
            if (!replayStartWall_) {
                replayStartWall_ = now;
                replayStartFile_ = pending_->timestamp;
            }
            using SteadyDuration = std::chrono::steady_clock::duration;
            const auto offset = std::chrono::duration_cast<SteadyDuration>(pending_->timestamp - *replayStartFile_);
            auto target = *replayStartWall_ + offset;
            // Cap long idle gaps so sparse captures still replay at a watchable pace.
            constexpr auto kMaxGap = std::chrono::seconds(2);
            if (target - now > kMaxGap) {
                replayStartWall_ = now + kMaxGap - offset;
                target = now + kMaxGap;
            }
            if (target > now) {
                if (target - now > timeout) {
                    std::this_thread::sleep_for(timeout);
                    return ReadStatus::Timeout;
                }
                std::this_thread::sleep_until(target);
            }
        }

        out = std::move(*pending_);
        pending_.reset();
        return ReadStatus::Packet;
    }

    [[nodiscard]] std::string description() const override {
        return "pcap:" + path_ + (realtime_ ? " (realtime replay)" : "");
    }

private:
    [[nodiscard]] std::uint32_t field(const std::uint8_t* data) const noexcept {
        const std::uint32_t value = loadNative32(data);
        return swapped_ ? byteSwap32(value) : value;
    }

    std::optional<RawPacket> readRecord() {
        std::array<std::uint8_t, kRecordHeaderSize> header{};
        if (!stream_.read(reinterpret_cast<char*>(header.data()), header.size())) {
            return std::nullopt;  // clean EOF or truncated trailer
        }
        const std::uint32_t seconds = field(header.data());
        const std::uint32_t fraction = field(header.data() + 4);
        const std::uint32_t includedLength = field(header.data() + 8);
        const std::uint32_t originalLength = field(header.data() + 12);
        if (includedLength > kMaxRecordLength) {
            throw CaptureError("corrupt pcap record (length " + std::to_string(includedLength) + ") in " + path_);
        }

        RawPacket packet;
        packet.bytes.resize(includedLength);
        if (includedLength > 0 &&
            !stream_.read(reinterpret_cast<char*>(packet.bytes.data()), static_cast<std::streamsize>(includedLength))) {
            return std::nullopt;  // truncated last record
        }
        packet.originalLength = std::max(originalLength, includedLength);
        packet.linkType = linkType_;
        const auto subSecond = nanosecond_ ? std::chrono::nanoseconds(fraction)
                                           : std::chrono::nanoseconds(std::chrono::microseconds(fraction));
        packet.timestamp = Clock::time_point(std::chrono::duration_cast<Clock::duration>(
            std::chrono::seconds(seconds) + subSecond));
        return packet;
    }

    std::string path_;
    bool realtime_;
    std::ifstream stream_;
    bool swapped_ = false;
    bool nanosecond_ = false;
    LinkType linkType_ = LinkType::Ethernet;
    std::optional<RawPacket> pending_;
    std::optional<std::chrono::steady_clock::time_point> replayStartWall_;
    std::optional<Clock::time_point> replayStartFile_;
};

}  // namespace

std::unique_ptr<CaptureSource> openPcapFile(const std::string& path, bool realtime) {
    return std::make_unique<PcapFileSource>(path, realtime);
}

// ---------------------------------------------------------------------------
// PcapWriter
// ---------------------------------------------------------------------------

PcapWriter::PcapWriter(const std::string& path) : stream_(path, std::ios::binary | std::ios::trunc) {
    if (!stream_) {
        throw CaptureError("cannot create pcap file: " + path);
    }
}

void PcapWriter::writeHeader(LinkType linkType) {
    std::array<std::uint8_t, kFileHeaderSize> header{};
    storeNative32(header.data(), kMagicMicroseconds);
    storeNative16(header.data() + 4, 2);  // version major
    storeNative16(header.data() + 6, 4);  // version minor
    storeNative32(header.data() + 16, kMaxRecordLength);
    storeNative32(header.data() + 20, linkType == LinkType::Ethernet ? kLinkTypeEthernet : kLinkTypeRaw);
    stream_.write(reinterpret_cast<const char*>(header.data()), header.size());
    linkType_ = linkType;
    headerWritten_ = true;
}

bool PcapWriter::write(const RawPacket& packet) {
    if (!headerWritten_) {
        writeHeader(packet.linkType);
    }
    if (packet.linkType != linkType_ || !stream_) {
        return false;
    }

    const auto sinceEpoch = packet.timestamp.time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(sinceEpoch);
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(sinceEpoch - seconds);
    const auto included = static_cast<std::uint32_t>(std::min<std::size_t>(packet.bytes.size(), kMaxRecordLength));

    std::array<std::uint8_t, kRecordHeaderSize> header{};
    storeNative32(header.data(), static_cast<std::uint32_t>(seconds.count()));
    storeNative32(header.data() + 4, static_cast<std::uint32_t>(micros.count()));
    storeNative32(header.data() + 8, included);
    storeNative32(header.data() + 12, std::max(packet.originalLength, included));
    stream_.write(reinterpret_cast<const char*>(header.data()), header.size());
    stream_.write(reinterpret_cast<const char*>(packet.bytes.data()), static_cast<std::streamsize>(included));
    if (!stream_) {
        return false;
    }
    ++written_;
    return true;
}

}  // namespace tpi
