#include "NetworkSniffer.hpp"
#include "PacketBuffer.hpp"
#include "TestFramework.hpp"

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

using namespace tpi;

namespace {

RawPacket makePacket(std::uint8_t marker, std::size_t length = 64) {
    RawPacket packet;
    packet.bytes.assign(length, marker);
    packet.originalLength = static_cast<std::uint32_t>(length);
    packet.timestamp = Clock::now();
    return packet;
}

/// Temporary file that is removed when the test scope ends (RAII).
class TempFile {
public:
    explicit TempFile(std::string name) : path_(std::move(name)) {}
    ~TempFile() { std::remove(path_.c_str()); }
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    [[nodiscard]] const std::string& path() const { return path_; }

private:
    std::string path_;
};

}  // namespace

TPI_TEST(packet_buffer_preserves_fifo_order) {
    PacketBuffer buffer(8);
    for (std::uint8_t i = 0; i < 5; ++i) {
        CHECK(buffer.push(makePacket(i)));
    }
    std::vector<RawPacket> out;
    CHECK_EQ(buffer.drain(out, 3), 3u);
    CHECK_EQ(out[0].bytes[0], 0);
    CHECK_EQ(out[2].bytes[0], 2);
    CHECK_EQ(buffer.size(), 2u);
}

TPI_TEST(packet_buffer_overwrites_oldest_when_full) {
    PacketBuffer buffer(4);
    for (std::uint8_t i = 0; i < 10; ++i) {
        buffer.push(makePacket(i));
    }
    CHECK_EQ(buffer.size(), 4u);
    CHECK_EQ(buffer.droppedCount(), 6u);
    std::vector<RawPacket> out;
    buffer.drain(out, 100);
    CHECK_EQ(out.front().bytes[0], 6);
    CHECK_EQ(out.back().bytes[0], 9);
}

TPI_TEST(packet_buffer_rejects_push_after_close) {
    PacketBuffer buffer(4);
    buffer.push(makePacket(1));
    buffer.close();
    CHECK(!buffer.push(makePacket(2)));
    CHECK(buffer.waitForData(std::chrono::milliseconds(1)));  // queued data is still drainable
    std::vector<RawPacket> out;
    CHECK_EQ(buffer.drain(out, 10), 1u);
    CHECK(!buffer.waitForData(std::chrono::milliseconds(1)));
}

TPI_TEST(pcap_writer_and_reader_round_trip) {
    const TempFile file("tpi_roundtrip_test.pcap");
    {
        PcapWriter writer(file.path());
        for (std::uint8_t i = 0; i < 3; ++i) {
            CHECK(writer.write(makePacket(i, 60 + i)));
        }
        CHECK_EQ(writer.packetsWritten(), 3u);
    }
    auto source = openPcapFile(file.path(), false);
    RawPacket packet;
    for (std::uint8_t i = 0; i < 3; ++i) {
        CHECK(source->read(packet, std::chrono::milliseconds(10)) == ReadStatus::Packet);
        CHECK_EQ(packet.bytes.size(), 60u + i);
        CHECK_EQ(packet.bytes[0], i);
        CHECK(packet.linkType == LinkType::Ethernet);
    }
    CHECK(source->read(packet, std::chrono::milliseconds(10)) == ReadStatus::EndOfStream);
}

TPI_TEST(pcap_reader_rejects_garbage) {
    const TempFile file("tpi_garbage_test.pcap");
    {
        std::FILE* raw = std::fopen(file.path().c_str(), "wb");
        CHECK(raw != nullptr);
        const char junk[32] = "definitely not a pcap file....";
        std::fwrite(junk, 1, sizeof junk, raw);
        std::fclose(raw);
    }
    bool threw = false;
    try {
        (void)openPcapFile(file.path(), false);
    } catch (const CaptureError&) {
        threw = true;
    }
    CHECK(threw);
}

TPI_TEST(sniffer_pumps_synthetic_stream_into_buffer) {
    PacketBuffer buffer(4096);
    SyntheticOptions options;
    options.packetsPerSecond = 2000;
    options.seed = 42;
    {
        NetworkSniffer sniffer(openSyntheticSource(options), buffer);
        sniffer.start();
        CHECK(buffer.waitForData(std::chrono::seconds(2)));
        sniffer.stop();
        CHECK(sniffer.capturedPackets() > 0);
    }  // destructor must join cleanly even after an explicit stop()
    CHECK(buffer.closed());
    std::vector<RawPacket> out;
    buffer.drain(out, 4096);
    CHECK(!out.empty());
    for (const auto& packet : out) {
        CHECK(packet.bytes.size() >= 60);  // minimum Ethernet frame
    }
}
