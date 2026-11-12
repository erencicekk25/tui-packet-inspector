// Virtual capture stream: synthesizes byte-exact Ethernet frames that look like a small
// office network sharing a wire with an industrial (OT) segment running Modbus.
// Every checksum is computed for real, so a recorded demo opens cleanly in Wireshark.

#include "NetworkSniffer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <deque>
#include <random>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace tpi {
namespace {

using Bytes = std::vector<std::uint8_t>;
using Mac = std::array<std::uint8_t, 6>;
using Ipv4 = std::array<std::uint8_t, 4>;
using Ipv6 = std::array<std::uint8_t, 16>;
using SteadyClock = std::chrono::steady_clock;

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeArp = 0x0806;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;
constexpr std::uint8_t kProtoIcmp = 1;
constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kProtoUdp = 17;
constexpr std::size_t kMinEthernetFrame = 60;

constexpr std::uint8_t kFin = 0x01;
constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kRst = 0x04;
constexpr std::uint8_t kPsh = 0x08;
constexpr std::uint8_t kAck = 0x10;

struct Host {
    Mac mac;
    Ipv4 ip;
};

// --- byte helpers ----------------------------------------------------------

void put16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void put32(Bytes& out, std::uint32_t value) {
    put16(out, static_cast<std::uint16_t>(value >> 16));
    put16(out, static_cast<std::uint16_t>(value & 0xFFFF));
}

void set16(Bytes& out, std::size_t offset, std::uint16_t value) {
    out[offset] = static_cast<std::uint8_t>(value >> 8);
    out[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
}

template <typename Container>
void append(Bytes& out, const Container& data) {
    out.insert(out.end(), std::begin(data), std::end(data));
}

std::uint32_t checksumAdd(const std::uint8_t* data, std::size_t length, std::uint32_t sum) {
    for (std::size_t i = 0; i + 1 < length; i += 2) {
        sum += static_cast<std::uint32_t>((data[i] << 8) | data[i + 1]);
    }
    if (length % 2 != 0) {
        sum += static_cast<std::uint32_t>(data[length - 1] << 8);
    }
    return sum;
}

std::uint16_t checksumFinish(std::uint32_t sum) {
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFF);
}

std::uint32_t pseudoHeaderV4(const Ipv4& src, const Ipv4& dst, std::uint8_t protocol, std::size_t length) {
    std::uint32_t sum = checksumAdd(src.data(), src.size(), 0);
    sum = checksumAdd(dst.data(), dst.size(), sum);
    return sum + protocol + static_cast<std::uint32_t>(length);
}

std::uint32_t pseudoHeaderV6(const Ipv6& src, const Ipv6& dst, std::uint8_t nextHeader, std::size_t length) {
    std::uint32_t sum = checksumAdd(src.data(), src.size(), 0);
    sum = checksumAdd(dst.data(), dst.size(), sum);
    return sum + nextHeader + static_cast<std::uint32_t>(length);
}

// --- protocol builders -----------------------------------------------------

Bytes ethernet(const Mac& dst, const Mac& src, std::uint16_t etherType, const Bytes& payload) {
    Bytes frame;
    frame.reserve(14 + payload.size());
    append(frame, dst);
    append(frame, src);
    put16(frame, etherType);
    append(frame, payload);
    if (frame.size() < kMinEthernetFrame) {
        frame.resize(kMinEthernetFrame, 0);  // Ethernet padding
    }
    return frame;
}

Bytes ipv4(const Ipv4& src, const Ipv4& dst, std::uint8_t protocol, const Bytes& payload, std::uint16_t id,
           std::uint8_t ttl) {
    Bytes packet;
    packet.reserve(20 + payload.size());
    packet.push_back(0x45);  // version 4, IHL 5
    packet.push_back(0x00);  // DSCP / ECN
    put16(packet, static_cast<std::uint16_t>(20 + payload.size()));
    put16(packet, id);
    put16(packet, 0x4000);  // Don't Fragment
    packet.push_back(ttl);
    packet.push_back(protocol);
    put16(packet, 0);  // checksum placeholder
    append(packet, src);
    append(packet, dst);
    set16(packet, 10, checksumFinish(checksumAdd(packet.data(), 20, 0)));
    append(packet, payload);
    return packet;
}

Bytes tcp(std::uint16_t srcPort, std::uint16_t dstPort, std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
          const Bytes& payload, std::uint32_t pseudoSum) {
    Bytes segment;
    segment.reserve(20 + payload.size());
    put16(segment, srcPort);
    put16(segment, dstPort);
    put32(segment, seq);
    put32(segment, ack);
    segment.push_back(0x50);  // data offset 5 words
    segment.push_back(flags);
    put16(segment, 64240);  // window
    put16(segment, 0);      // checksum placeholder
    put16(segment, 0);      // urgent pointer
    append(segment, payload);
    set16(segment, 16, checksumFinish(checksumAdd(segment.data(), segment.size(), pseudoSum)));
    return segment;
}

Bytes udp(std::uint16_t srcPort, std::uint16_t dstPort, const Bytes& payload, std::uint32_t pseudoSum) {
    Bytes datagram;
    datagram.reserve(8 + payload.size());
    put16(datagram, srcPort);
    put16(datagram, dstPort);
    put16(datagram, static_cast<std::uint16_t>(8 + payload.size()));
    put16(datagram, 0);
    append(datagram, payload);
    std::uint16_t checksum = checksumFinish(checksumAdd(datagram.data(), datagram.size(), pseudoSum));
    set16(datagram, 6, checksum == 0 ? 0xFFFF : checksum);
    return datagram;
}

Bytes dnsQuery(std::uint16_t id, const std::string& name) {
    Bytes query;
    put16(query, id);
    put16(query, 0x0100);  // standard query, recursion desired
    put16(query, 1);       // QDCOUNT
    put16(query, 0);
    put16(query, 0);
    put16(query, 0);
    std::size_t start = 0;
    while (start <= name.size()) {
        const std::size_t dot = std::min(name.find('.', start), name.size());
        query.push_back(static_cast<std::uint8_t>(dot - start));
        query.insert(query.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                     name.begin() + static_cast<std::ptrdiff_t>(dot));
        start = dot + 1;
    }
    query.push_back(0);
    put16(query, 1);  // QTYPE A
    put16(query, 1);  // QCLASS IN
    return query;
}

std::uint16_t modbusCrc(const Bytes& data) {
    std::uint16_t crc = 0xFFFF;
    for (const std::uint8_t byte : data) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1) != 0 ? static_cast<std::uint16_t>((crc >> 1) ^ 0xA001) : static_cast<std::uint16_t>(crc >> 1);
        }
    }
    return crc;
}

// --- the generator -----------------------------------------------------------

class SyntheticSource final : public CaptureSource {
public:
    explicit SyntheticSource(const SyntheticOptions& options)
        : options_(options),
          rng_(options.seed != 0 ? options.seed : std::random_device{}()),
          start_(SteadyClock::now()),
          nextEmit_(start_) {
        options_.packetsPerSecond = std::clamp(options_.packetsPerSecond, 1.0, 200000.0);
        for (std::uint8_t i = 0; i < 8; ++i) {
            lanClients_.push_back(Host{{0x3C, 0x52, 0x82, 0x10, 0x00, static_cast<std::uint8_t>(0x21 + i)},
                                       {10, 0, 0, static_cast<std::uint8_t>(21 + i)}});
        }
        modbusSessions_ = {
            ModbusSession{hmi_, 49712, random32(), random32()},
            ModbusSession{scada_, 50211, random32(), random32()},
        };
    }

    ReadStatus read(RawPacket& out, std::chrono::milliseconds timeout) override {
        const auto deadline = SteadyClock::now() + timeout;
        for (;;) {
            const auto now = SteadyClock::now();
            if (!pending_.empty() && pending_.front().due <= now) {
                emit(out, std::move(pending_.front().frame));
                pending_.pop_front();
                return ReadStatus::Packet;
            }
            if (nextEmit_ <= now) {
                emit(out, generate(now));
                std::exponential_distribution<double> gap(rateAt(now));
                nextEmit_ += std::chrono::duration_cast<SteadyClock::duration>(std::chrono::duration<double>(gap(rng_)));
                if (now - nextEmit_ > std::chrono::milliseconds(500)) {
                    nextEmit_ = now;  // consumer was too slow; do not try to catch up forever
                }
                return ReadStatus::Packet;
            }
            if (now >= deadline) {
                return ReadStatus::Timeout;
            }
            auto wake = nextEmit_;
            if (!pending_.empty()) {
                wake = std::min(wake, pending_.front().due);
            }
            std::this_thread::sleep_until(std::min(wake, deadline));
        }
    }

    [[nodiscard]] std::string description() const override {
        return "demo (virtual stream, ~" + std::to_string(static_cast<long>(options_.packetsPerSecond)) + " pkt/s)";
    }

private:
    struct Scheduled {
        SteadyClock::time_point due;
        Bytes frame;
    };

    struct ModbusSession {
        Host client;
        std::uint16_t clientPort;
        std::uint32_t clientSeq;
        std::uint32_t serverSeq;
    };

    static void emit(RawPacket& out, Bytes frame) {
        out.originalLength = static_cast<std::uint32_t>(frame.size());
        out.bytes = std::move(frame);
        out.timestamp = Clock::now();
        out.linkType = LinkType::Ethernet;
    }

    /// Traffic rate with slow waves plus a periodic burst, so the live graph has something to show.
    double rateAt(SteadyClock::time_point now) const {
        constexpr double kTwoPi = 6.283185307179586;
        const double t = std::chrono::duration<double>(now - start_).count();
        double factor = 0.75 + 0.30 * std::sin(t * kTwoPi / 20.0) + 0.12 * std::sin(t * kTwoPi / 3.7);
        if (std::fmod(t, 17.0) < 1.8) {
            factor *= 2.4;  // burst
        }
        return std::max(1.0, options_.packetsPerSecond * factor);
    }

    void schedule(SteadyClock::time_point due, Bytes frame) {
        const auto position = std::upper_bound(pending_.begin(), pending_.end(), due,
                                               [](const auto& time, const Scheduled& item) { return time < item.due; });
        pending_.insert(position, Scheduled{due, std::move(frame)});
    }

    /// Uniform integer in [low, high]. Byte-sized types are widened because
    /// std::uniform_int_distribution does not accept character types.
    template <typename T>
    T pick(T low, T high) {
        using Wide = std::conditional_t<(sizeof(T) < sizeof(int)), int, T>;
        return static_cast<T>(std::uniform_int_distribution<Wide>(low, high)(rng_));
    }

    std::uint32_t random32() { return static_cast<std::uint32_t>(rng_()); }

    bool chance(double probability) { return std::bernoulli_distribution(probability)(rng_); }

    std::uint16_t ephemeralPort() { return pick<std::uint16_t>(49152, 65535); }

    Bytes ipv4Frame(const Host& src, const Host& dst, std::uint8_t protocol, const Bytes& l4, std::uint8_t ttl = 64) {
        return ethernet(dst.mac, src.mac, kEtherTypeIpv4, ipv4(src.ip, dst.ip, protocol, l4, ++ipId_, ttl));
    }

    Bytes tcpFrame(const Host& src, const Host& dst, std::uint16_t sport, std::uint16_t dport, std::uint32_t seq,
                   std::uint32_t ack, std::uint8_t flags, const Bytes& payload, std::uint8_t ttl = 64) {
        const Bytes segment = tcp(sport, dport, seq, ack, flags, payload,
                                  pseudoHeaderV4(src.ip, dst.ip, kProtoTcp, 20 + payload.size()));
        return ipv4Frame(src, dst, kProtoTcp, segment, ttl);
    }

    Bytes udpFrame(const Host& src, const Host& dst, std::uint16_t sport, std::uint16_t dport, const Bytes& payload) {
        const Bytes datagram = udp(sport, dport, payload, pseudoHeaderV4(src.ip, dst.ip, kProtoUdp, 8 + payload.size()));
        return ipv4Frame(src, dst, kProtoUdp, datagram);
    }

    Bytes generate(SteadyClock::time_point now) {
        // web, modbus/tcp, dns, ntp+syslog, arp, icmp, mdns(v6), modbus/rtu-over-udp
        static const std::array<double, 8> kWeights{38, 24, 14, 6, 5, 5, 4, 4};
        std::discrete_distribution<int> kind(kWeights.begin(), kWeights.end());
        switch (kind(rng_)) {
            case 0: return webTraffic();
            case 1: return modbusTcpExchange(now);
            case 2: return dnsTraffic(now);
            case 3: return infrastructureUdp();
            case 4: return arpRequest();
            case 5: return icmpEcho(now);
            case 6: return mdnsAnnouncement();
            default: return modbusRtuOverUdp(now);
        }
    }

    Bytes webTraffic() {
        const Host& client = lanClients_[pick<std::size_t>(0, lanClients_.size() - 1)];
        static const std::array<Ipv4, 4> kServers{{{93, 184, 216, 34}, {140, 82, 121, 4}, {151, 101, 1, 69}, {104, 16, 132, 229}}};
        const Host server{gateway_.mac, kServers[pick<std::size_t>(0, kServers.size() - 1)]};
        const bool tls = chance(0.8);
        const std::uint16_t serverPort = tls ? 443 : 80;
        const std::uint16_t clientPort = ephemeralPort();
        const bool upstream = chance(0.4);
        const std::uint32_t seq = random32();
        const std::uint32_t ack = random32();

        const double roll = std::uniform_real_distribution<double>(0.0, 1.0)(rng_);
        std::uint8_t flags = kAck;
        Bytes payload;
        if (roll < 0.03) {
            flags = upstream ? kSyn : static_cast<std::uint8_t>(kSyn | kAck);
        } else if (roll < 0.05) {
            flags = kFin | kAck;
        } else if (roll < 0.06) {
            flags = kRst;
        } else if (roll < 0.70) {
            flags = kPsh | kAck;
            if (!tls && upstream) {
                const std::string request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5\r\n\r\n";
                payload.assign(request.begin(), request.end());
            } else {
                const std::size_t length = upstream ? pick<std::size_t>(40, 600) : pick<std::size_t>(200, 1400);
                payload = {0x17, 0x03, 0x03};  // TLS application data record
                put16(payload, static_cast<std::uint16_t>(length));
                while (payload.size() < length + 5) {
                    payload.push_back(static_cast<std::uint8_t>(rng_()));
                }
            }
        }

        if (upstream) {
            return ethernet(gateway_.mac, client.mac, kEtherTypeIpv4,
                            tcpFrameL3(client.ip, server.ip, clientPort, serverPort, seq, ack, flags, payload, 64));
        }
        return ethernet(client.mac, gateway_.mac, kEtherTypeIpv4,
                        tcpFrameL3(server.ip, client.ip, serverPort, clientPort, seq, ack, flags, payload, 54));
    }

    Bytes tcpFrameL3(const Ipv4& src, const Ipv4& dst, std::uint16_t sport, std::uint16_t dport, std::uint32_t seq,
                     std::uint32_t ack, std::uint8_t flags, const Bytes& payload, std::uint8_t ttl) {
        const Bytes segment =
            tcp(sport, dport, seq, ack, flags, payload, pseudoHeaderV4(src, dst, kProtoTcp, 20 + payload.size()));
        return ipv4(src, dst, kProtoTcp, segment, ++ipId_, ttl);
    }

    Bytes modbusPdu(std::uint8_t function, bool request, std::uint16_t address, std::uint16_t quantity) {
        Bytes pdu{function};
        switch (function) {
            case 0x01:
            case 0x02:
            case 0x03:
            case 0x04:
                if (request) {
                    put16(pdu, address);
                    put16(pdu, quantity);
                } else {
                    const std::size_t byteCount = function <= 0x02 ? (quantity + 7u) / 8u : quantity * 2u;
                    pdu.push_back(static_cast<std::uint8_t>(byteCount));
                    for (std::size_t i = 0; i < byteCount; i += 2) {
                        put16(pdu, static_cast<std::uint16_t>(2000 + pick<int>(-150, 150)));  // sensor-like values
                    }
                    pdu.resize(2 + byteCount);
                }
                break;
            case 0x05:
                put16(pdu, address);
                put16(pdu, chance(0.5) ? 0xFF00 : 0x0000);
                break;
            case 0x06:
                put16(pdu, address);
                put16(pdu, pick<std::uint16_t>(0, 4000));
                break;
            case 0x10:
                put16(pdu, address);
                put16(pdu, quantity);
                if (request) {
                    pdu.push_back(static_cast<std::uint8_t>(quantity * 2));
                    for (std::uint16_t i = 0; i < quantity; ++i) {
                        put16(pdu, pick<std::uint16_t>(0, 4000));
                    }
                }
                break;
            default:
                break;
        }
        return pdu;
    }

    struct ModbusTransaction {
        Bytes request;
        Bytes response;
    };

    ModbusTransaction modbusTransaction() {
        static const std::array<std::uint8_t, 7> kFunctions{0x03, 0x04, 0x01, 0x02, 0x06, 0x10, 0x05};
        static const std::array<double, 7> kWeights{45, 15, 10, 5, 10, 10, 5};
        std::discrete_distribution<std::size_t> select(kWeights.begin(), kWeights.end());
        const std::uint8_t function = kFunctions[select(rng_)];
        const std::uint16_t address = pick<std::uint16_t>(0, 400);
        const std::uint16_t quantity = function <= 0x02 ? pick<std::uint16_t>(1, 32) : pick<std::uint16_t>(1, 16);

        ModbusTransaction transaction;
        transaction.request = modbusPdu(function, true, address, quantity);
        if (chance(0.04)) {
            static const std::array<std::uint8_t, 4> kExceptions{0x02, 0x02, 0x01, 0x0B};
            transaction.response = {static_cast<std::uint8_t>(function | 0x80),
                                    kExceptions[pick<std::size_t>(0, kExceptions.size() - 1)]};
        } else if (function == 0x05 || function == 0x06) {
            transaction.response = transaction.request;  // write single echoes the request
        } else {
            transaction.response = modbusPdu(function, false, address, quantity);
        }
        return transaction;
    }

    SteadyClock::duration responseDelay() {
        const int millis = chance(0.03) ? pick<int>(40, 120) : pick<int>(2, 12);
        return std::chrono::milliseconds(millis) + std::chrono::microseconds(pick<int>(0, 999));
    }

    Bytes modbusTcpExchange(SteadyClock::time_point now) {
        ModbusSession& session = modbusSessions_[pick<std::size_t>(0, modbusSessions_.size() - 1)];
        const ModbusTransaction transaction = modbusTransaction();
        const std::uint8_t unit = pick<std::uint8_t>(1, 3);
        const std::uint16_t tid = ++modbusTid_;

        auto adu = [&](const Bytes& pdu) {
            Bytes out;
            put16(out, tid);
            put16(out, 0);  // protocol identifier: Modbus
            put16(out, static_cast<std::uint16_t>(pdu.size() + 1));
            out.push_back(unit);
            append(out, pdu);
            return out;
        };

        const Bytes request = adu(transaction.request);
        const Bytes response = adu(transaction.response);
        const std::uint16_t port = options_.modbusPort;

        Bytes requestFrame = tcpFrame(session.client, plc_, session.clientPort, port, session.clientSeq,
                                      session.serverSeq, kPsh | kAck, request);
        session.clientSeq += static_cast<std::uint32_t>(request.size());
        Bytes responseFrame = tcpFrame(plc_, session.client, port, session.clientPort, session.serverSeq,
                                       session.clientSeq, kPsh | kAck, response);
        session.serverSeq += static_cast<std::uint32_t>(response.size());

        schedule(now + responseDelay(), std::move(responseFrame));
        return requestFrame;
    }

    Bytes modbusRtuOverUdp(SteadyClock::time_point now) {
        // A serial-to-Ethernet gateway tunnelling raw Modbus RTU frames (with CRC) over UDP.
        const ModbusTransaction transaction = modbusTransaction();
        const std::uint8_t slave = pick<std::uint8_t>(10, 12);
        auto rtu = [&](const Bytes& pdu) {
            Bytes frame{slave};
            append(frame, pdu);
            const std::uint16_t crc = modbusCrc(frame);
            frame.push_back(static_cast<std::uint8_t>(crc & 0xFF));  // CRC is little-endian on the wire
            frame.push_back(static_cast<std::uint8_t>(crc >> 8));
            return frame;
        };
        const std::uint16_t port = options_.modbusPort;
        schedule(now + responseDelay() + std::chrono::milliseconds(8),
                 udpFrame(serialGateway_, scada_, port, 40502, rtu(transaction.response)));
        return udpFrame(scada_, serialGateway_, 40502, port, rtu(transaction.request));
    }

    Bytes dnsTraffic(SteadyClock::time_point now) {
        static const std::array<const char*, 6> kNames{"github.com", "api.github.com", "example.org",
                                                       "updates.vendor.io", "time.cloudflare.com", "plc-01.ot.lan"};
        const Host& client = lanClients_[pick<std::size_t>(0, lanClients_.size() - 1)];
        const std::uint16_t id = pick<std::uint16_t>(1, 65535);
        const std::uint16_t port = ephemeralPort();
        Bytes query = dnsQuery(id, kNames[pick<std::size_t>(0, kNames.size() - 1)]);
        Bytes answer = query;
        set16(answer, 2, 0x8180);  // standard response, no error
        set16(answer, 6, 1);       // ANCOUNT
        const Bytes record{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
                           93,   184,  216,  34};
        append(answer, record);
        const Host resolver{gateway_.mac, dnsServer_.ip};
        schedule(now + std::chrono::milliseconds(pick<int>(8, 30)), udpFrame(resolver, client, 53, port, answer));
        return udpFrame(client, resolver, port, 53, query);
    }

    Bytes infrastructureUdp() {
        const Host& client = lanClients_[pick<std::size_t>(0, lanClients_.size() - 1)];
        if (chance(0.5)) {
            Bytes ntp(48, 0);
            ntp[0] = 0x23;  // LI=0, VN=4, Mode=3 (client)
            const Host server{gateway_.mac, {162, 159, 200, 1}};
            return udpFrame(client, server, 123, 123, ntp);
        }
        const std::string message = "<134>1 - plc-01 modbusd - - - poll cycle completed";
        const Host collector{lanClients_.front().mac, {10, 0, 0, 5}};
        return udpFrame(plc_, collector, 514, 514, Bytes(message.begin(), message.end()));
    }

    Bytes arpRequest() {
        const Host& sender = lanClients_[pick<std::size_t>(0, lanClients_.size() - 1)];
        Bytes arp;
        put16(arp, 1);       // hardware type: Ethernet
        put16(arp, 0x0800);  // protocol type: IPv4
        arp.push_back(6);
        arp.push_back(4);
        put16(arp, 1);  // operation: request
        append(arp, sender.mac);
        append(arp, sender.ip);
        append(arp, Mac{});
        append(arp, Ipv4{10, 0, 0, static_cast<std::uint8_t>(pick<int>(1, 40))});
        return ethernet(Mac{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, sender.mac, kEtherTypeArp, arp);
    }

    Bytes icmpEcho(SteadyClock::time_point now) {
        const Host& client = lanClients_[pick<std::size_t>(0, lanClients_.size() - 1)];
        const Host target{gateway_.mac, {1, 1, 1, 1}};
        const std::uint16_t id = pick<std::uint16_t>(1, 65535);
        const std::uint16_t sequence = ++icmpSequence_;
        auto message = [&](std::uint8_t type) {
            Bytes icmp{type, 0, 0, 0};
            put16(icmp, id);
            put16(icmp, sequence);
            for (std::uint8_t i = 0; i < 32; ++i) {
                icmp.push_back(static_cast<std::uint8_t>('a' + i % 23));
            }
            set16(icmp, 2, checksumFinish(checksumAdd(icmp.data(), icmp.size(), 0)));
            return icmp;
        };
        Bytes reply = ethernet(client.mac, gateway_.mac, kEtherTypeIpv4,
                               ipv4(target.ip, client.ip, kProtoIcmp, message(0), ++ipId_, 57));
        schedule(now + std::chrono::milliseconds(pick<int>(9, 25)), std::move(reply));
        return ipv4Frame(client, target, kProtoIcmp, message(8));
    }

    Bytes mdnsAnnouncement() {
        const Host& client = lanClients_[pick<std::size_t>(0, lanClients_.size() - 1)];
        Ipv6 source{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x3E, 0x52, 0x82, 0xFF, 0xFE, 0x10, 0x00, client.mac[5]};
        const Ipv6 destination{0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB};
        Bytes query = dnsQuery(0, "_services._dns-sd._udp.local");
        set16(query, 2, 0x0000);
        const Bytes datagram =
            udp(5353, 5353, query, pseudoHeaderV6(source, destination, kProtoUdp, 8 + query.size()));
        Bytes packet{0x60, 0x00, 0x00, 0x00};
        put16(packet, static_cast<std::uint16_t>(datagram.size()));
        packet.push_back(kProtoUdp);
        packet.push_back(255);  // hop limit
        append(packet, source);
        append(packet, destination);
        append(packet, datagram);
        return ethernet(Mac{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}, client.mac, kEtherTypeIpv6, packet);
    }

    SyntheticOptions options_;
    std::mt19937 rng_;
    SteadyClock::time_point start_;
    SteadyClock::time_point nextEmit_;
    std::deque<Scheduled> pending_;  // future frames (responses), ordered by due time
    std::uint16_t ipId_ = 0;
    std::uint16_t modbusTid_ = 0;
    std::uint16_t icmpSequence_ = 0;

    std::vector<Host> lanClients_;
    Host gateway_{{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01}, {10, 0, 0, 1}};
    Host dnsServer_{{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01}, {1, 1, 1, 1}};
    Host plc_{{0x00, 0x80, 0xF4, 0x0A, 0x00, 0x10}, {192, 168, 1, 10}};
    Host hmi_{{0x00, 0x0E, 0x8C, 0x55, 0x00, 0x32}, {192, 168, 1, 50}};
    Host scada_{{0x00, 0x0E, 0x8C, 0x55, 0x00, 0x3C}, {192, 168, 1, 60}};
    Host serialGateway_{{0x00, 0x20, 0x4A, 0x99, 0x00, 0x50}, {192, 168, 1, 80}};
    std::vector<ModbusSession> modbusSessions_;
};

}  // namespace

std::unique_ptr<CaptureSource> openSyntheticSource(const SyntheticOptions& options) {
    return std::make_unique<SyntheticSource>(options);
}

}  // namespace tpi
