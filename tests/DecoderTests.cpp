#include "ProtocolDecoder.hpp"
#include "TestFramework.hpp"

#include <random>
#include <string>
#include <vector>

using namespace tpi;

namespace {

using Bytes = std::vector<std::uint8_t>;

void put16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

/// Ethernet + IPv4 (no checksum) + transport header + payload.
RawPacket buildIpv4Frame(std::uint8_t protocol, const Bytes& transport) {
    Bytes frame{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00};
    frame.push_back(0x45);
    frame.push_back(0x00);
    put16(frame, static_cast<std::uint16_t>(20 + transport.size()));
    put16(frame, 0x1234);
    put16(frame, 0x4000);
    frame.push_back(64);
    frame.push_back(protocol);
    put16(frame, 0);  // checksum 0 = "offloaded", skipped by the validator
    for (std::uint8_t b : {192, 168, 1, 50, 192, 168, 1, 10}) {
        frame.push_back(b);
    }
    frame.insert(frame.end(), transport.begin(), transport.end());
    RawPacket packet;
    packet.originalLength = static_cast<std::uint32_t>(frame.size());
    packet.bytes = std::move(frame);
    return packet;
}

Bytes tcpSegment(std::uint16_t sport, std::uint16_t dport, std::uint8_t flags, const Bytes& payload) {
    Bytes tcp;
    put16(tcp, sport);
    put16(tcp, dport);
    put16(tcp, 0);
    put16(tcp, 1000);  // seq = 1000
    put16(tcp, 0);
    put16(tcp, 2000);  // ack = 2000
    tcp.push_back(0x50);
    tcp.push_back(flags);
    put16(tcp, 8192);
    put16(tcp, 0);
    put16(tcp, 0);
    tcp.insert(tcp.end(), payload.begin(), payload.end());
    return tcp;
}

Bytes udpDatagram(std::uint16_t sport, std::uint16_t dport, const Bytes& payload) {
    Bytes udp;
    put16(udp, sport);
    put16(udp, dport);
    put16(udp, static_cast<std::uint16_t>(8 + payload.size()));
    put16(udp, 0);
    udp.insert(udp.end(), payload.begin(), payload.end());
    return udp;
}

}  // namespace

TPI_TEST(modbus_crc16_matches_reference_vector) {
    // Classic example: read 10 holding registers from slave 1 -> CRC bytes C5 CD.
    const Bytes request{0x01, 0x03, 0x00, 0x00, 0x00, 0x0A};
    CHECK_EQ(ProtocolDecoder::modbusCrc16(ByteView(request)), 0xCDC5);
}

TPI_TEST(decodes_tcp_header_and_flags) {
    const ProtocolDecoder decoder;
    const DecodedPacket packet =
        decoder.decode(buildIpv4Frame(6, tcpSegment(51234, 443, TcpFlag::Syn | TcpFlag::Ack, {})));
    CHECK(packet.protocol == Protocol::Tcp);
    CHECK(packet.tcp.has_value());
    CHECK_EQ(packet.tcp->sourcePort, 51234);
    CHECK_EQ(packet.tcp->destinationPort, 443);
    CHECK_EQ(packet.tcp->sequence, 1000u);
    CHECK_EQ(packet.tcp->flagString(), std::string("SYN,ACK"));
    CHECK_EQ(packet.application, std::string("HTTPS"));
    CHECK_EQ(packet.source(), std::string("192.168.1.50:51234"));
    CHECK(!packet.malformed());
}

TPI_TEST(decodes_udp_and_strips_ethernet_padding) {
    const ProtocolDecoder decoder;
    RawPacket raw = buildIpv4Frame(17, udpDatagram(5353, 53, {0xAB, 0xCD}));
    raw.bytes.resize(60, 0);  // Ethernet minimum-frame padding must not leak into the payload
    const DecodedPacket packet = decoder.decode(raw);
    CHECK(packet.protocol == Protocol::Udp);
    CHECK_EQ(packet.udp->payloadLength, 2u);
    CHECK_EQ(packet.application, std::string("DNS"));
}

TPI_TEST(decodes_modbus_tcp_read_holding_registers_request) {
    const ProtocolDecoder decoder;
    const Bytes adu{0x00, 0x2A, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x0A};
    const DecodedPacket packet = decoder.decode(buildIpv4Frame(6, tcpSegment(49712, 502, TcpFlag::Psh | TcpFlag::Ack, adu)));
    CHECK(packet.protocol == Protocol::Modbus);
    CHECK(packet.modbus.has_value());
    const ModbusFrame& frame = *packet.modbus;
    CHECK(frame.framing == ModbusFraming::Tcp);
    CHECK(frame.direction == ModbusDirection::Request);
    CHECK_EQ(frame.transactionId, 42);
    CHECK_EQ(frame.unitId, 1);
    CHECK_EQ(frame.functionCode, 3);
    CHECK_EQ(*frame.startAddress, 100);
    CHECK_EQ(*frame.quantity, 10);
    CHECK(packet.summary().find("Read Holding Registers req addr=100 qty=10") != std::string::npos);
}

TPI_TEST(decodes_modbus_exception_response) {
    const ProtocolDecoder decoder;
    const Bytes adu{0x00, 0x2A, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02};
    const DecodedPacket packet = decoder.decode(buildIpv4Frame(6, tcpSegment(502, 49712, TcpFlag::Psh | TcpFlag::Ack, adu)));
    CHECK(packet.modbus.has_value());
    CHECK(packet.modbus->isException);
    CHECK_EQ(packet.modbus->functionCode, 3);
    CHECK_EQ(packet.modbus->exceptionCode, 2);
    CHECK(packet.summary().find("Illegal Data Address") != std::string::npos);
}

TPI_TEST(counts_pipelined_modbus_adus) {
    const ProtocolDecoder decoder;
    const Bytes adus{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
                     0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01};
    const DecodedPacket packet = decoder.decode(buildIpv4Frame(6, tcpSegment(49712, 502, TcpFlag::Psh, adus)));
    CHECK(packet.modbus.has_value());
    CHECK_EQ(packet.modbus->aduCount, 2u);
}

TPI_TEST(decodes_modbus_rtu_over_udp) {
    const ProtocolDecoder decoder;
    const Bytes rtu{0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    const DecodedPacket packet = decoder.decode(buildIpv4Frame(17, udpDatagram(40502, 502, rtu)));
    CHECK(packet.protocol == Protocol::Modbus);
    CHECK(packet.modbus->framing == ModbusFraming::Rtu);
    CHECK(*packet.modbus->crcValid);
    CHECK_EQ(*packet.modbus->quantity, 10);
}

TPI_TEST(flags_garbage_on_modbus_port) {
    const ProtocolDecoder decoder;
    const Bytes junk{'H', 'E', 'L', 'L', 'O', ' ', 'P', 'L', 'C', '!'};
    const DecodedPacket packet = decoder.decode(buildIpv4Frame(6, tcpSegment(40000, 502, TcpFlag::Psh, junk)));
    CHECK(packet.protocol == Protocol::Tcp);
    CHECK(packet.malformed());
}

TPI_TEST(custom_modbus_port_is_respected) {
    DecoderOptions options;
    options.modbusPorts = {5020};
    const ProtocolDecoder decoder(options);
    const Bytes adu{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x10, 0x01, 0xF4};
    const DecodedPacket packet = decoder.decode(buildIpv4Frame(6, tcpSegment(40000, 5020, TcpFlag::Psh, adu)));
    CHECK(packet.modbus.has_value());
    CHECK_EQ(*packet.modbus->value, 500);
}

TPI_TEST(reports_truncated_headers_without_crashing) {
    const ProtocolDecoder decoder;
    RawPacket raw = buildIpv4Frame(6, tcpSegment(1, 2, 0, {}));
    raw.bytes.resize(14 + 20 + 10);  // cut inside the TCP header
    const DecodedPacket packet = decoder.decode(raw);
    CHECK(packet.protocol == Protocol::Ipv4);
    CHECK(packet.malformed());
}

TPI_TEST(formats_ipv6_addresses_rfc5952) {
    IpAddress address;
    address.version = 6;
    address.bytes = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    CHECK_EQ(address.toString(), std::string("fe80::1"));
    address.bytes = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x01};
    CHECK_EQ(address.toString(), std::string("2001:db8:0:1::1"));
}

TPI_TEST(fuzz_random_bytes_never_crash) {
    const ProtocolDecoder decoder;
    std::mt19937 rng(1337);
    std::uniform_int_distribution<int> byte(0, 255);
    std::uniform_int_distribution<int> length(0, 200);
    for (int iteration = 0; iteration < 20000; ++iteration) {
        RawPacket raw;
        raw.bytes.resize(static_cast<std::size_t>(length(rng)));
        for (auto& b : raw.bytes) {
            b = static_cast<std::uint8_t>(byte(rng));
        }
        if (raw.bytes.size() > 13 && iteration % 2 == 0) {
            raw.bytes[12] = 0x08;  // bias half the corpus towards IPv4 so deeper layers get exercised
            raw.bytes[13] = 0x00;
        }
        raw.linkType = iteration % 5 == 0 ? LinkType::RawIp : LinkType::Ethernet;
        const DecodedPacket packet = decoder.decode(raw);
        (void)packet.summary();
        (void)packet.source();
        (void)packet.destination();
    }
}
