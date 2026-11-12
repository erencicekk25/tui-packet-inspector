#pragma once

#include "ByteView.hpp"
#include "Packet.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tpi {

/// Highest protocol layer that was successfully decoded.
enum class Protocol : std::uint8_t { Unknown, Arp, Ipv4, Ipv6, Icmp, Tcp, Udp, Modbus };

[[nodiscard]] const char* protocolName(Protocol protocol) noexcept;

struct MacAddress {
    std::array<std::uint8_t, 6> bytes{};
    [[nodiscard]] std::string toString() const;
};

struct IpAddress {
    std::uint8_t version = 0;              ///< 4 or 6; 0 = unset
    std::array<std::uint8_t, 16> bytes{};  ///< IPv4 uses the first 4 bytes
    [[nodiscard]] std::string toString() const;  ///< Dotted quad / RFC 5952 compressed IPv6
};

struct EthernetHeader {
    MacAddress destination;
    MacAddress source;
    std::uint16_t etherType = 0;
    std::optional<std::uint16_t> vlanId;
};

struct ArpHeader {
    std::uint16_t operation = 0;  ///< 1 = request, 2 = reply
    MacAddress senderMac;
    IpAddress senderIp;
    IpAddress targetIp;
};

struct IpHeader {
    std::uint8_t version = 0;
    IpAddress source;
    IpAddress destination;
    std::uint8_t protocol = 0;  ///< IPv4 protocol / IPv6 final next-header
    std::uint8_t ttl = 0;       ///< TTL / hop limit
    std::uint16_t totalLength = 0;
    std::uint8_t headerLength = 0;
    bool checksumValid = true;  ///< IPv4 header checksum (always true for IPv6)
    bool fragment = false;      ///< Non-first fragment: transport header is not present
};

struct IcmpHeader {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
    bool v6 = false;
};

namespace TcpFlag {
constexpr std::uint8_t Fin = 0x01;
constexpr std::uint8_t Syn = 0x02;
constexpr std::uint8_t Rst = 0x04;
constexpr std::uint8_t Psh = 0x08;
constexpr std::uint8_t Ack = 0x10;
constexpr std::uint8_t Urg = 0x20;
constexpr std::uint8_t Ece = 0x40;
constexpr std::uint8_t Cwr = 0x80;
}  // namespace TcpFlag

struct TcpHeader {
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    std::uint32_t sequence = 0;
    std::uint32_t acknowledgment = 0;
    std::uint8_t flags = 0;
    std::uint16_t window = 0;
    std::uint8_t headerLength = 0;
    std::size_t payloadLength = 0;
    [[nodiscard]] std::string flagString() const;  ///< e.g. "SYN,ACK"
};

struct UdpHeader {
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    std::uint16_t length = 0;
    std::size_t payloadLength = 0;
};

enum class ModbusFraming : std::uint8_t { Tcp, Rtu };
enum class ModbusDirection : std::uint8_t { Request, Response, Unknown };

/// A decoded Modbus application data unit (first ADU when several share one segment).
struct ModbusFrame {
    ModbusFraming framing = ModbusFraming::Tcp;
    ModbusDirection direction = ModbusDirection::Unknown;

    // MBAP header (Modbus/TCP only)
    std::uint16_t transactionId = 0;
    std::uint16_t protocolId = 0;
    std::uint16_t length = 0;

    std::uint8_t unitId = 0;        ///< MBAP unit identifier / RTU slave address
    std::uint8_t functionCode = 0;  ///< Without the exception bit
    bool isException = false;
    std::uint8_t exceptionCode = 0;

    std::optional<std::uint16_t> startAddress;
    std::optional<std::uint16_t> quantity;
    std::optional<std::uint16_t> value;  ///< Write Single Coil / Register
    std::optional<std::uint8_t> byteCount;
    std::optional<bool> crcValid;  ///< RTU only
    std::size_t aduCount = 1;      ///< ADUs packed into the same TCP segment

    [[nodiscard]] std::string describe() const;
};

[[nodiscard]] const char* modbusFunctionName(std::uint8_t functionCode) noexcept;
[[nodiscard]] const char* modbusExceptionName(std::uint8_t exceptionCode) noexcept;

/// Result of decoding one RawPacket; every layer is optional.
struct DecodedPacket {
    Clock::time_point timestamp{};
    std::size_t capturedLength = 0;
    std::size_t wireLength = 0;

    std::optional<EthernetHeader> ethernet;
    std::optional<ArpHeader> arp;
    std::optional<IpHeader> ip;
    std::optional<IcmpHeader> icmp;
    std::optional<TcpHeader> tcp;
    std::optional<UdpHeader> udp;
    std::optional<ModbusFrame> modbus;

    Protocol protocol = Protocol::Unknown;  ///< Highest decoded layer
    std::string application;                ///< Well-known service hint by port, e.g. "HTTPS"
    std::vector<std::string> issues;        ///< Truncation / malformation notes

    [[nodiscard]] std::string source() const;       ///< "10.0.0.5:51234", "[fe80::1]:5353", MAC, ...
    [[nodiscard]] std::string destination() const;
    [[nodiscard]] std::string summary() const;      ///< One-line, Wireshark-style info column
    [[nodiscard]] bool malformed() const noexcept { return !issues.empty(); }
};

struct DecoderOptions {
    std::vector<std::uint16_t> modbusPorts{502};  ///< TCP/UDP ports carrying Modbus
    bool validateIpChecksum = true;
};

/// Stateless, allocation-light protocol parser:
/// Ethernet (+802.1Q) -> ARP | IPv4 | IPv6 -> ICMP | TCP | UDP -> Modbus/TCP | Modbus/RTU.
///
/// decode() never throws on bad input and never reads out of bounds; problems are reported
/// in DecodedPacket::issues instead.
class ProtocolDecoder {
public:
    explicit ProtocolDecoder(DecoderOptions options = {});

    [[nodiscard]] DecodedPacket decode(const RawPacket& packet) const;

    /// Parses a Modbus/TCP payload (MBAP header + PDU). Returns nullopt if it is not Modbus.
    [[nodiscard]] static std::optional<ModbusFrame> decodeModbusTcp(ByteView payload,
                                                                    ModbusDirection direction = ModbusDirection::Unknown);
    /// Parses a Modbus RTU frame (address + PDU + CRC16). Returns nullopt if the CRC does not match.
    [[nodiscard]] static std::optional<ModbusFrame> decodeModbusRtu(ByteView frame,
                                                                    ModbusDirection direction = ModbusDirection::Unknown);
    /// Modbus CRC-16 (polynomial 0xA001, initial value 0xFFFF).
    [[nodiscard]] static std::uint16_t modbusCrc16(ByteView data) noexcept;

private:
    void decodeEthernet(ByteView frame, DecodedPacket& out) const;
    void decodeNetwork(std::uint16_t etherType, ByteView payload, DecodedPacket& out) const;
    void decodeArp(ByteView payload, DecodedPacket& out) const;
    void decodeIpv4(ByteView packet, DecodedPacket& out) const;
    void decodeIpv6(ByteView packet, DecodedPacket& out) const;
    void decodeTransport(std::uint8_t protocol, ByteView segment, DecodedPacket& out) const;
    void decodeTcp(ByteView segment, DecodedPacket& out) const;
    void decodeUdp(ByteView datagram, DecodedPacket& out) const;
    void decodeApplication(ByteView payload, std::uint16_t sourcePort, std::uint16_t destinationPort, bool overTcp,
                           DecodedPacket& out) const;
    [[nodiscard]] bool isModbusPort(std::uint16_t port) const noexcept;

    DecoderOptions options_;
};

}  // namespace tpi
