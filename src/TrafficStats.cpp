#include "TrafficStats.hpp"

#include <algorithm>
#include <cstdio>

namespace tpi {

namespace {

/// Key that pairs a Modbus request with its response: client, server and transaction.
std::string transactionKey(const std::string& client, const std::string& server, const ModbusFrame& frame) {
    const unsigned discriminator = frame.framing == ModbusFraming::Tcp
                                       ? frame.transactionId
                                       : 0x10000u + (static_cast<unsigned>(frame.unitId) << 8) + frame.functionCode;
    return client + '>' + server + '#' + std::to_string(discriminator);
}

}  // namespace

TrafficStats::TrafficStats(std::chrono::milliseconds sampleInterval, std::size_t historyLength)
    : sampleInterval_(std::max(sampleInterval, std::chrono::milliseconds(50))),
      historyLength_(std::max<std::size_t>(historyLength, 8)),
      bucketStart_(SteadyClock::now()) {}

void TrafficStats::reset() {
    *this = TrafficStats(sampleInterval_, historyLength_);
}

void TrafficStats::record(const DecodedPacket& packet) {
    ++totalPackets_;
    totalBytes_ += packet.wireLength;
    ++bucketPackets_;
    bucketBytes_ += packet.wireLength;
    ++protocolCounts_[static_cast<std::size_t>(packet.protocol)];
    if (packet.malformed()) {
        ++malformed_;
    }
    if (packet.tcp) {
        if ((packet.tcp->flags & TcpFlag::Rst) != 0) {
            ++tcpResets_;
        }
        if ((packet.tcp->flags & TcpFlag::Syn) != 0 && (packet.tcp->flags & TcpFlag::Ack) == 0) {
            ++tcpSyns_;
        }
    }

    std::string address;
    if (packet.ip) {
        address = packet.ip->source.toString();
    } else if (packet.arp) {
        address = packet.arp->senderIp.toString();
    } else if (packet.ethernet) {
        address = packet.ethernet->source.toString();
    }
    if (!address.empty()) {
        auto it = talkers_.find(address);
        if (it == talkers_.end() && talkers_.size() < kMaxTalkers) {
            it = talkers_.emplace(address, TalkerStat{address, 0, 0}).first;
        }
        if (it != talkers_.end()) {
            ++it->second.packets;
            it->second.bytes += packet.wireLength;
        }
    }

    if (packet.modbus) {
        recordModbus(packet);
    }
}

void TrafficStats::recordModbus(const DecodedPacket& packet) {
    const ModbusFrame& frame = *packet.modbus;
    ++modbus_.functionCounts[frame.functionCode & 0x7F];

    const std::string source = packet.source();
    const std::string destination = packet.destination();

    if (frame.direction == ModbusDirection::Request) {
        ++modbus_.requests;
        if (pendingTransactions_.size() >= kMaxPendingTransactions) {
            pendingTransactions_.clear();  // unanswered requests: drop rather than grow forever
        }
        pendingTransactions_[transactionKey(source, destination, frame)] = packet.timestamp;
        return;
    }
    if (frame.direction != ModbusDirection::Response) {
        return;  // e.g. RTU between two non-standard ports: cannot tell which side is which
    }

    ++modbus_.responses;
    if (frame.isException) {
        ++modbus_.exceptions;
        char function[8];
        std::snprintf(function, sizeof function, "FC%02u", static_cast<unsigned>(frame.functionCode));
        modbus_.lastException = std::string(modbusExceptionName(frame.exceptionCode)) + " (" + function + ", unit " +
                                std::to_string(frame.unitId) + ")";
    }
    const auto it = pendingTransactions_.find(transactionKey(destination, source, frame));
    if (it != pendingTransactions_.end()) {
        const double latency = std::chrono::duration<double, std::milli>(packet.timestamp - it->second).count();
        if (latency >= 0.0) {
            ++modbus_.matchedTransactions;
            modbus_.latencySumMs += latency;
            modbus_.latencyMaxMs = std::max(modbus_.latencyMaxMs, latency);
            modbus_.lastLatencyMs = latency;
        }
        pendingTransactions_.erase(it);
    }
}

void TrafficStats::advance(SteadyClock::time_point now) {
    const double seconds = std::chrono::duration<double>(sampleInterval_).count();
    while (now - bucketStart_ >= sampleInterval_) {
        const double packetRate = static_cast<double>(bucketPackets_) / seconds;
        packetRates_.push_back(packetRate);
        byteRates_.push_back(static_cast<double>(bucketBytes_) / seconds);
        peakPacketRate_ = std::max(peakPacketRate_, packetRate);
        if (packetRates_.size() > historyLength_) {
            packetRates_.pop_front();
            byteRates_.pop_front();
        }
        bucketPackets_ = 0;
        bucketBytes_ = 0;
        bucketStart_ += sampleInterval_;
        if (now - bucketStart_ > sampleInterval_ * static_cast<long>(historyLength_)) {
            bucketStart_ = now;  // process was suspended; do not replay thousands of empty buckets
        }
    }
}

std::vector<TalkerStat> TrafficStats::topTalkers(std::size_t limit) const {
    std::vector<TalkerStat> result;
    result.reserve(talkers_.size());
    for (const auto& entry : talkers_) {
        result.push_back(entry.second);
    }
    const std::size_t count = std::min(limit, result.size());
    std::partial_sort(result.begin(), result.begin() + static_cast<std::ptrdiff_t>(count), result.end(),
                      [](const TalkerStat& a, const TalkerStat& b) {
                          return a.bytes != b.bytes ? a.bytes > b.bytes : a.address < b.address;
                      });
    result.resize(count);
    return result;
}

}  // namespace tpi
