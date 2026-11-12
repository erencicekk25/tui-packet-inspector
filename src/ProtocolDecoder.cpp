#include "ProtocolDecoder.hpp"

#include <algorithm>
#include <cstdio>
#include <utility>

namespace tpi {
namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeArp = 0x0806;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;
constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;

constexpr std::uint8_t kIpProtoIcmp = 1;
constexpr std::uint8_t kIpProtoTcp = 6;
constexpr std::uint8_t kIpProtoUdp = 17;
constexpr std::uint8_t kIpProtoIcmpV6 = 58;

constexpr std::uint8_t kIpv6HopByHop = 0;
constexpr std::uint8_t kIpv6Routing = 43;
constexpr std::uint8_t kIpv6Fragment = 44;
constexpr std::uint8_t kIpv6DestinationOptions = 60;
constexpr int kMaxIpv6ExtensionHeaders = 8;

constexpr std::size_t kMbapHeaderSize = 7;
constexpr std::uint16_t kModbusMaxLength = 254;  // unit id + 253-byte PDU

const char* serviceName(std::uint16_t port) noexcept {
    switch (port) {
        case 20:
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67:
        case 68: return "DHCP";
        case 80: return "HTTP";
        case 102: return "S7comm";
        case 123: return "NTP";
        case 161:
        case 162: return "SNMP";
        case 443: return "HTTPS";
        case 502: return "Modbus";
        case 514: return "Syslog";
        case 1883: return "MQTT";
        case 2404: return "IEC-104";
        case 3389: return "RDP";
        case 4840: return "OPC-UA";
        case 5353: return "mDNS";
        case 8080: return "HTTP-Alt";
        case 8883: return "MQTTS";
        case 20000: return "DNP3";
        case 44818: return "EtherNet/IP";
        case 47808: return "BACnet";
        default: return nullptr;
    }
}

const char* icmpTypeName(std::uint8_t type, bool v6) noexcept {
    if (v6) {
        switch (type) {
            case 1: return "Destination unreachable";
            case 2: return "Packet too big";
            case 3: return "Time exceeded";
            case 128: return "Echo request";
            case 129: return "Echo reply";
            case 133: return "Router solicitation";
            case 134: return "Router advertisement";
            case 135: return "Neighbor solicitation";
            case 136: return "Neighbor advertisement";
            default: return nullptr;
        }
    }
    switch (type) {
        case 0: return "Echo reply";
        case 3: return "Destination unreachable";
        case 5: return "Redirect";
        case 8: return "Echo request";
        case 11: return "Time exceeded";
        default: return nullptr;
    }
}

std::string formatEndpoint(const IpAddress& address, std::optional<std::uint16_t> port) {
    if (!port) {
        return address.toString();
    }
    if (address.version == 6) {
        return "[" + address.toString() + "]:" + std::to_string(*port);
    }
    return address.toString() + ":" + std::to_string(*port);
}

IpAddress readIpv4(ByteView view, std::size_t offset) {
    IpAddress address;
    address.version = 4;
    for (std::size_t i = 0; i < 4; ++i) {
        address.bytes[i] = view.u8(offset + i);
    }
    return address;
}

IpAddress readIpv6(ByteView view, std::size_t offset) {
    IpAddress address;
    address.version = 6;
    for (std::size_t i = 0; i < 16; ++i) {
        address.bytes[i] = view.u8(offset + i);
    }
    return address;
}

MacAddress readMac(ByteView view, std::size_t offset) {
    MacAddress mac;
    for (std::size_t i = 0; i < 6; ++i) {
        mac.bytes[i] = view.u8(offset + i);
    }
    return mac;
}

/// Parses the function-specific part of a Modbus PDU. `frame.direction` is used as a hint
/// and refined from the PDU shape when it is still unknown (e.g. RTU on a serial tap).
bool parseModbusPdu(ByteView pdu, ModbusFrame& frame) {
    if (pdu.empty()) {
        return false;
    }
    const std::uint8_t rawFunction = pdu.u8(0);
    frame.isException = (rawFunction & 0x80) != 0;
    frame.functionCode = rawFunction & 0x7F;
    if (frame.functionCode == 0) {
        return false;
    }
    if (frame.isException) {
        if (!pdu.has(1, 1)) {
            return false;
        }
        frame.exceptionCode = pdu.u8(1);
        frame.direction = ModbusDirection::Response;
        return true;
    }

    const bool unknown = frame.direction == ModbusDirection::Unknown;
    switch (frame.functionCode) {
        case 0x01:
        case 0x02:
        case 0x03:
        case 0x04: {
            const bool request = frame.direction == ModbusDirection::Request || (unknown && pdu.size() == 5);
            if (request) {
                if (pdu.has(1, 4)) {
                    frame.startAddress = pdu.be16(1);
                    frame.quantity = pdu.be16(3);
                }
                frame.direction = ModbusDirection::Request;
            } else {
                if (pdu.has(1, 1)) {
                    frame.byteCount = pdu.u8(1);
                }
                frame.direction = ModbusDirection::Response;
            }
            break;
        }
        case 0x05:
        case 0x06:
            if (pdu.has(1, 4)) {
                frame.startAddress = pdu.be16(1);
                frame.value = pdu.be16(3);
            }
            break;  // request and response are identical; keep the port-based direction
        case 0x0F:
        case 0x10:
            if (pdu.has(1, 4)) {
                frame.startAddress = pdu.be16(1);
                frame.quantity = pdu.be16(3);
            }
            if (frame.direction != ModbusDirection::Response && pdu.has(5, 1)) {
                frame.byteCount = pdu.u8(5);
                frame.direction = ModbusDirection::Request;
            } else if (unknown && pdu.size() == 5) {
                frame.direction = ModbusDirection::Response;
            }
            break;
        default:
            break;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Names and formatting
// ---------------------------------------------------------------------------

const char* protocolName(Protocol protocol) noexcept {
    switch (protocol) {
        case Protocol::Arp: return "ARP";
        case Protocol::Ipv4: return "IPv4";
        case Protocol::Ipv6: return "IPv6";
        case Protocol::Icmp: return "ICMP";
        case Protocol::Tcp: return "TCP";
        case Protocol::Udp: return "UDP";
        case Protocol::Modbus: return "Modbus";
        case Protocol::Unknown: break;
    }
    return "Other";
}

const char* modbusFunctionName(std::uint8_t functionCode) noexcept {
    switch (functionCode) {
        case 0x01: return "Read Coils";
        case 0x02: return "Read Discrete Inputs";
        case 0x03: return "Read Holding Registers";
        case 0x04: return "Read Input Registers";
        case 0x05: return "Write Single Coil";
        case 0x06: return "Write Single Register";
        case 0x07: return "Read Exception Status";
        case 0x08: return "Diagnostics";
        case 0x0B: return "Get Comm Event Counter";
        case 0x0C: return "Get Comm Event Log";
        case 0x0F: return "Write Multiple Coils";
        case 0x10: return "Write Multiple Registers";
        case 0x11: return "Report Server ID";
        case 0x14: return "Read File Record";
        case 0x15: return "Write File Record";
        case 0x16: return "Mask Write Register";
        case 0x17: return "Read/Write Multiple Registers";
        case 0x18: return "Read FIFO Queue";
        case 0x2B: return "Encapsulated Interface Transport";
        default: return "Unknown Function";
    }
}

const char* modbusExceptionName(std::uint8_t exceptionCode) noexcept {
    switch (exceptionCode) {
        case 0x01: return "Illegal Function";
        case 0x02: return "Illegal Data Address";
        case 0x03: return "Illegal Data Value";
        case 0x04: return "Server Device Failure";
        case 0x05: return "Acknowledge";
        case 0x06: return "Server Device Busy";
        case 0x08: return "Memory Parity Error";
        case 0x0A: return "Gateway Path Unavailable";
        case 0x0B: return "Gateway Target Failed to Respond";
        default: return "Unknown Exception";
    }
}

std::string MacAddress::toString() const {
    char text[18];
    std::snprintf(text, sizeof text, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3],
                  bytes[4], bytes[5]);
    return text;
}

std::string IpAddress::toString() const {
    if (version == 4) {
        return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." + std::to_string(bytes[2]) + "." +
               std::to_string(bytes[3]);
    }
    if (version != 6) {
        return "?";
    }

    std::array<std::uint16_t, 8> groups{};
    for (std::size_t i = 0; i < 8; ++i) {
        groups[i] = static_cast<std::uint16_t>((bytes[2 * i] << 8) | bytes[2 * i + 1]);
    }
    // RFC 5952: compress the longest run (>= 2) of zero groups, leftmost on ties.
    int bestStart = -1;
    int bestLength = 0;
    for (int i = 0; i < 8;) {
        if (groups[static_cast<std::size_t>(i)] != 0) {
            ++i;
            continue;
        }
        int j = i;
        while (j < 8 && groups[static_cast<std::size_t>(j)] == 0) {
            ++j;
        }
        if (j - i > bestLength && j - i >= 2) {
            bestStart = i;
            bestLength = j - i;
        }
        i = j;
    }

    std::string text;
    char group[8];
    for (int i = 0; i < 8; ++i) {
        if (i == bestStart) {
            text += "::";
            i += bestLength - 1;
            continue;
        }
        if (!text.empty() && text.back() != ':') {
            text += ':';
        }
        std::snprintf(group, sizeof group, "%x", groups[static_cast<std::size_t>(i)]);
        text += group;
    }
    return text;
}

std::string TcpHeader::flagString() const {
    static constexpr std::pair<std::uint8_t, const char*> kNames[] = {
        {TcpFlag::Syn, "SYN"}, {TcpFlag::Fin, "FIN"}, {TcpFlag::Rst, "RST"}, {TcpFlag::Psh, "PSH"},
        {TcpFlag::Ack, "ACK"}, {TcpFlag::Urg, "URG"}, {TcpFlag::Ece, "ECE"}, {TcpFlag::Cwr, "CWR"},
    };
    std::string text;
    for (const auto& [bit, name] : kNames) {
        if ((flags & bit) != 0) {
            if (!text.empty()) {
                text += ',';
            }
            text += name;
        }
    }
    return text.empty() ? "none" : text;
}

std::string ModbusFrame::describe() const {
    std::string text;
    if (isException) {
        char code[8];
        std::snprintf(code, sizeof code, "0x%02X", exceptionCode);
        text = std::string("EXCEPTION ") + modbusFunctionName(functionCode) + ": " +
               modbusExceptionName(exceptionCode) + " (" + code + ")";
    } else {
        text = modbusFunctionName(functionCode);
        if (direction == ModbusDirection::Request) {
            text += " req";
        } else if (direction == ModbusDirection::Response) {
            text += " resp";
        }
        if (startAddress) {
            text += " addr=" + std::to_string(*startAddress);
        }
        if (quantity) {
            text += " qty=" + std::to_string(*quantity);
        }
        if (value) {
            text += " value=" + std::to_string(*value);
        }
        if (byteCount && direction == ModbusDirection::Response) {
            text += " bytes=" + std::to_string(*byteCount);
        }
    }

    text += " (unit " + std::to_string(unitId);
    if (framing == ModbusFraming::Tcp) {
        text += ", tid " + std::to_string(transactionId);
    } else {
        text += ", RTU";
        if (crcValid) {
            text += *crcValid ? " crc ok" : " crc BAD";
        }
    }
    text += ")";
    if (aduCount > 1) {
        text += " +" + std::to_string(aduCount - 1) + " ADU";
    }
    return text;
}

std::string DecodedPacket::source() const {
    if (ip) {
        std::optional<std::uint16_t> port;
        if (tcp) {
            port = tcp->sourcePort;
        } else if (udp) {
            port = udp->sourcePort;
        }
        return formatEndpoint(ip->source, port);
    }
    if (arp) {
        return arp->senderIp.toString();
    }
    if (ethernet) {
        return ethernet->source.toString();
    }
    return "?";
}

std::string DecodedPacket::destination() const {
    if (ip) {
        std::optional<std::uint16_t> port;
        if (tcp) {
            port = tcp->destinationPort;
        } else if (udp) {
            port = udp->destinationPort;
        }
        return formatEndpoint(ip->destination, port);
    }
    if (arp) {
        return arp->targetIp.toString();
    }
    if (ethernet) {
        return ethernet->destination.toString();
    }
    return "?";
}

std::string DecodedPacket::summary() const {
    std::string text;
    if (modbus) {
        text = modbus->describe();
    } else if (tcp) {
        text = std::to_string(tcp->sourcePort) + " -> " + std::to_string(tcp->destinationPort) + " [" +
               tcp->flagString() + "] seq=" + std::to_string(tcp->sequence);
        if ((tcp->flags & TcpFlag::Ack) != 0) {
            text += " ack=" + std::to_string(tcp->acknowledgment);
        }
        text += " win=" + std::to_string(tcp->window) + " len=" + std::to_string(tcp->payloadLength);
    } else if (udp) {
        text = std::to_string(udp->sourcePort) + " -> " + std::to_string(udp->destinationPort) +
               " len=" + std::to_string(udp->payloadLength);
    } else if (icmp) {
        const char* name = icmpTypeName(icmp->type, icmp->v6);
        text = name != nullptr ? name : "type " + std::to_string(icmp->type);
        text += " (code " + std::to_string(icmp->code) + ")";
    } else if (arp) {
        if (arp->operation == 1) {
            text = "Who has " + arp->targetIp.toString() + "? Tell " + arp->senderIp.toString();
        } else if (arp->operation == 2) {
            text = arp->senderIp.toString() + " is at " + arp->senderMac.toString();
        } else {
            text = "ARP operation " + std::to_string(arp->operation);
        }
    } else if (ip) {
        text = "IP protocol " + std::to_string(ip->protocol);
        if (ip->fragment) {
            text += " (fragment)";
        }
    } else if (ethernet) {
        char type[8];
        std::snprintf(type, sizeof type, "0x%04x", ethernet->etherType);
        text = std::string("EtherType ") + type;
    }

    if (!application.empty() && !modbus) {
        text = application + "  " + text;
    }
    if (!issues.empty()) {
        text += text.empty() ? "" : "  ";
        text += "[!] " + issues.front();
    }
    return text;
}

// ---------------------------------------------------------------------------
// ProtocolDecoder
// ---------------------------------------------------------------------------

ProtocolDecoder::ProtocolDecoder(DecoderOptions options) : options_(std::move(options)) {}

bool ProtocolDecoder::isModbusPort(std::uint16_t port) const noexcept {
    return std::find(options_.modbusPorts.begin(), options_.modbusPorts.end(), port) != options_.modbusPorts.end();
}

DecodedPacket ProtocolDecoder::decode(const RawPacket& packet) const {
    DecodedPacket out;
    out.timestamp = packet.timestamp;
    out.capturedLength = packet.bytes.size();
    out.wireLength = std::max<std::size_t>(packet.originalLength, packet.bytes.size());

    const ByteView view(packet.bytes);
    if (packet.linkType == LinkType::Ethernet) {
        decodeEthernet(view, out);
    } else if (!view.has(0, 1)) {
        out.issues.emplace_back("empty packet");
    } else if ((view.u8(0) >> 4) == 4) {
        decodeIpv4(view, out);
    } else if ((view.u8(0) >> 4) == 6) {
        decodeIpv6(view, out);
    } else {
        out.issues.emplace_back("unknown IP version");
    }
    return out;
}

void ProtocolDecoder::decodeEthernet(ByteView frame, DecodedPacket& out) const {
    if (!frame.has(0, 14)) {
        out.issues.emplace_back("truncated Ethernet header");
        return;
    }
    EthernetHeader header;
    header.destination = readMac(frame, 0);
    header.source = readMac(frame, 6);
    std::uint16_t etherType = frame.be16(12);
    std::size_t offset = 14;
    // 802.1Q / 802.1ad tags (possibly stacked)
    while ((etherType == kEtherTypeVlan || etherType == kEtherTypeQinQ) && frame.has(offset, 4)) {
        if (!header.vlanId) {
            header.vlanId = static_cast<std::uint16_t>(frame.be16(offset) & 0x0FFF);
        }
        etherType = frame.be16(offset + 2);
        offset += 4;
    }
    header.etherType = etherType;
    out.ethernet = header;
    decodeNetwork(etherType, frame.subview(offset), out);
}

void ProtocolDecoder::decodeNetwork(std::uint16_t etherType, ByteView payload, DecodedPacket& out) const {
    switch (etherType) {
        case kEtherTypeIpv4: decodeIpv4(payload, out); break;
        case kEtherTypeIpv6: decodeIpv6(payload, out); break;
        case kEtherTypeArp: decodeArp(payload, out); break;
        default: break;
    }
}

void ProtocolDecoder::decodeArp(ByteView payload, DecodedPacket& out) const {
    if (!payload.has(0, 28)) {
        out.issues.emplace_back("truncated ARP packet");
        return;
    }
    if (payload.be16(0) != 1 || payload.be16(2) != kEtherTypeIpv4 || payload.u8(4) != 6 || payload.u8(5) != 4) {
        out.issues.emplace_back("unsupported ARP hardware/protocol type");
        return;
    }
    ArpHeader arp;
    arp.operation = payload.be16(6);
    arp.senderMac = readMac(payload, 8);
    arp.senderIp = readIpv4(payload, 14);
    arp.targetIp = readIpv4(payload, 24);
    out.arp = arp;
    out.protocol = Protocol::Arp;
}

void ProtocolDecoder::decodeIpv4(ByteView packet, DecodedPacket& out) const {
    if (!packet.has(0, 20)) {
        out.issues.emplace_back("truncated IPv4 header");
        return;
    }
    const std::uint8_t versionIhl = packet.u8(0);
    const std::size_t headerLength = static_cast<std::size_t>(versionIhl & 0x0F) * 4;
    if ((versionIhl >> 4) != 4 || headerLength < 20 || !packet.has(0, headerLength)) {
        out.issues.emplace_back("invalid IPv4 header length");
        return;
    }

    IpHeader header;
    header.version = 4;
    header.headerLength = static_cast<std::uint8_t>(headerLength);
    header.totalLength = packet.be16(2);
    header.fragment = (packet.be16(6) & 0x1FFF) != 0;
    header.ttl = packet.u8(8);
    header.protocol = packet.u8(9);
    header.source = readIpv4(packet, 12);
    header.destination = readIpv4(packet, 16);

    // A zero checksum usually means checksum offloading on the capturing host, not corruption.
    if (options_.validateIpChecksum && packet.be16(10) != 0) {
        std::uint32_t sum = 0;
        for (std::size_t i = 0; i < headerLength; i += 2) {
            sum += packet.be16(i);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        header.checksumValid = sum == 0xFFFF;
        if (!header.checksumValid) {
            out.issues.emplace_back("bad IPv4 header checksum");
        }
    }

    out.ip = header;
    out.protocol = Protocol::Ipv4;

    // Total length 0 is seen with TCP segmentation offload; fall back to what was captured.
    std::size_t end = header.totalLength == 0 ? packet.size() : header.totalLength;
    if (end < headerLength) {
        out.issues.emplace_back("IPv4 total length smaller than header");
        return;
    }
    end = std::min(end, packet.size());  // also strips Ethernet padding
    if (header.fragment) {
        return;  // only the first fragment carries the transport header
    }
    decodeTransport(header.protocol, packet.subview(headerLength, end - headerLength), out);
}

void ProtocolDecoder::decodeIpv6(ByteView packet, DecodedPacket& out) const {
    if (!packet.has(0, 40)) {
        out.issues.emplace_back("truncated IPv6 header");
        return;
    }
    IpHeader header;
    header.version = 6;
    header.headerLength = 40;
    const std::uint16_t payloadLength = packet.be16(4);
    header.totalLength = static_cast<std::uint16_t>(std::min<std::size_t>(40u + payloadLength, 0xFFFF));
    header.ttl = packet.u8(7);
    header.source = readIpv6(packet, 8);
    header.destination = readIpv6(packet, 24);

    const std::size_t end = payloadLength == 0 ? packet.size() : std::min<std::size_t>(packet.size(), 40u + payloadLength);
    std::uint8_t next = packet.u8(6);
    std::size_t offset = 40;
    for (int i = 0; i < kMaxIpv6ExtensionHeaders; ++i) {
        if (next == kIpv6HopByHop || next == kIpv6Routing || next == kIpv6DestinationOptions) {
            if (!packet.has(offset, 2)) {
                break;
            }
            next = packet.u8(offset);
            offset += (static_cast<std::size_t>(packet.u8(offset + 1)) + 1) * 8;
        } else if (next == kIpv6Fragment) {
            if (!packet.has(offset, 8)) {
                break;
            }
            next = packet.u8(offset);
            header.fragment = (packet.be16(offset + 2) >> 3) != 0;
            offset += 8;
        } else {
            break;
        }
    }
    header.protocol = next;
    out.ip = header;
    out.protocol = Protocol::Ipv6;

    if (offset > end) {
        out.issues.emplace_back("truncated IPv6 extension headers");
        return;
    }
    if (header.fragment) {
        return;
    }
    decodeTransport(next, packet.subview(offset, end - offset), out);
}

void ProtocolDecoder::decodeTransport(std::uint8_t protocol, ByteView segment, DecodedPacket& out) const {
    switch (protocol) {
        case kIpProtoTcp: decodeTcp(segment, out); break;
        case kIpProtoUdp: decodeUdp(segment, out); break;
        case kIpProtoIcmp:
        case kIpProtoIcmpV6:
            if (!segment.has(0, 4)) {
                out.issues.emplace_back("truncated ICMP header");
                return;
            }
            out.icmp = IcmpHeader{segment.u8(0), segment.u8(1), protocol == kIpProtoIcmpV6};
            out.protocol = Protocol::Icmp;
            break;
        default: break;
    }
}

void ProtocolDecoder::decodeTcp(ByteView segment, DecodedPacket& out) const {
    if (!segment.has(0, 20)) {
        out.issues.emplace_back("truncated TCP header");
        return;
    }
    TcpHeader tcp;
    tcp.sourcePort = segment.be16(0);
    tcp.destinationPort = segment.be16(2);
    tcp.sequence = segment.be32(4);
    tcp.acknowledgment = segment.be32(8);
    const std::size_t dataOffset = static_cast<std::size_t>(segment.u8(12) >> 4) * 4;
    tcp.flags = segment.u8(13);
    tcp.window = segment.be16(14);
    if (dataOffset < 20) {
        out.issues.emplace_back("invalid TCP data offset");
        return;
    }
    out.protocol = Protocol::Tcp;
    if (!segment.has(0, dataOffset)) {
        out.tcp = tcp;
        out.issues.emplace_back("truncated TCP options");
        return;
    }
    tcp.headerLength = static_cast<std::uint8_t>(dataOffset);
    tcp.payloadLength = segment.size() - dataOffset;
    out.tcp = tcp;
    decodeApplication(segment.subview(dataOffset), tcp.sourcePort, tcp.destinationPort, true, out);
}

void ProtocolDecoder::decodeUdp(ByteView datagram, DecodedPacket& out) const {
    if (!datagram.has(0, 8)) {
        out.issues.emplace_back("truncated UDP header");
        return;
    }
    UdpHeader udp;
    udp.sourcePort = datagram.be16(0);
    udp.destinationPort = datagram.be16(2);
    udp.length = datagram.be16(4);
    std::size_t end = datagram.size();
    if (udp.length < 8) {
        out.issues.emplace_back("invalid UDP length");
    } else if (udp.length <= datagram.size()) {
        end = udp.length;
    }
    udp.payloadLength = end - 8;
    out.udp = udp;
    out.protocol = Protocol::Udp;
    decodeApplication(datagram.subview(8, end - 8), udp.sourcePort, udp.destinationPort, false, out);
}

void ProtocolDecoder::decodeApplication(ByteView payload, std::uint16_t sourcePort, std::uint16_t destinationPort,
                                        bool overTcp, DecodedPacket& out) const {
    // Service hint: prefer the lower (well-known) port.
    const std::uint16_t low = std::min(sourcePort, destinationPort);
    const std::uint16_t high = std::max(sourcePort, destinationPort);
    if (const char* service = serviceName(low)) {
        out.application = service;
    } else if (const char* fallback = serviceName(high)) {
        out.application = fallback;
    }

    const bool toModbus = isModbusPort(destinationPort);
    const bool fromModbus = isModbusPort(sourcePort);
    if (payload.empty() || (!toModbus && !fromModbus)) {
        return;
    }

    ModbusDirection direction = ModbusDirection::Unknown;
    if (toModbus && !fromModbus) {
        direction = ModbusDirection::Request;
    } else if (fromModbus && !toModbus) {
        direction = ModbusDirection::Response;
    }

    std::optional<ModbusFrame> frame;
    // Modbus/TCP over UDP must fill the datagram exactly; over TCP several ADUs may be packed.
    const bool exactMbap = payload.has(0, 6) && static_cast<std::size_t>(payload.be16(4)) + 6 == payload.size();
    if (overTcp || exactMbap) {
        frame = decodeModbusTcp(payload, direction);
    }
    if (!frame) {
        frame = decodeModbusRtu(payload, direction);  // RTU tunnelled through a serial gateway
    }
    if (frame) {
        out.modbus = std::move(frame);
        out.protocol = Protocol::Modbus;
        out.application = "Modbus";
    } else {
        out.issues.emplace_back("non-Modbus payload on Modbus port");
    }
}

std::optional<ModbusFrame> ProtocolDecoder::decodeModbusTcp(ByteView payload, ModbusDirection direction) {
    if (!payload.has(0, kMbapHeaderSize + 1)) {
        return std::nullopt;
    }
    ModbusFrame frame;
    frame.framing = ModbusFraming::Tcp;
    frame.direction = direction;
    frame.transactionId = payload.be16(0);
    frame.protocolId = payload.be16(2);
    frame.length = payload.be16(4);
    frame.unitId = payload.u8(6);
    if (frame.protocolId != 0 || frame.length < 2 || frame.length > kModbusMaxLength) {
        return std::nullopt;
    }
    if (!parseModbusPdu(payload.subview(kMbapHeaderSize, frame.length - 1u), frame)) {
        return std::nullopt;
    }

    // Count back-to-back ADUs in the same segment (pipelined requests).
    std::size_t count = 0;
    std::size_t offset = 0;
    while (payload.has(offset, kMbapHeaderSize + 1) && payload.be16(offset + 2) == 0) {
        const std::uint16_t length = payload.be16(offset + 4);
        if (length < 2 || length > kModbusMaxLength) {
            break;
        }
        ++count;
        offset += 6u + length;
    }
    frame.aduCount = std::max<std::size_t>(count, 1);
    return frame;
}

std::optional<ModbusFrame> ProtocolDecoder::decodeModbusRtu(ByteView rtu, ModbusDirection direction) {
    if (rtu.size() < 4 || rtu.size() > 256) {
        return std::nullopt;
    }
    const std::uint16_t expected = rtu.le16(rtu.size() - 2);
    if (modbusCrc16(rtu.subview(0, rtu.size() - 2)) != expected) {
        return std::nullopt;
    }
    ModbusFrame frame;
    frame.framing = ModbusFraming::Rtu;
    frame.direction = direction;
    frame.unitId = rtu.u8(0);
    frame.crcValid = true;
    if (!parseModbusPdu(rtu.subview(1, rtu.size() - 3), frame)) {
        return std::nullopt;
    }
    return frame;
}

std::uint16_t ProtocolDecoder::modbusCrc16(ByteView data) noexcept {
    std::uint16_t crc = 0xFFFF;
    for (std::size_t i = 0; i < data.size(); ++i) {
        crc ^= data.u8(i);
        for (int bit = 0; bit < 8; ++bit) {
            const bool lsb = (crc & 1) != 0;
            crc = static_cast<std::uint16_t>(crc >> 1);
            if (lsb) {
                crc ^= 0xA001;
            }
        }
    }
    return crc;
}

}  // namespace tpi
