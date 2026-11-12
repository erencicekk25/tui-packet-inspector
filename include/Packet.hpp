#pragma once

#include <chrono>
#include <cstdint>
#include <vector>

namespace tpi {

using Clock = std::chrono::system_clock;

/// Link-layer framing of a captured packet.
enum class LinkType : std::uint8_t {
    Ethernet,  ///< Frame starts with an Ethernet II header (DLT_EN10MB).
    RawIp      ///< Frame starts directly with an IPv4 / IPv6 header (DLT_RAW).
};

/// A single packet exactly as it was captured, before any decoding.
struct RawPacket {
    std::vector<std::uint8_t> bytes;   ///< Captured bytes (may be truncated to the snap length).
    std::uint32_t originalLength = 0;  ///< Length of the packet on the wire.
    Clock::time_point timestamp{};     ///< Capture time.
    LinkType linkType = LinkType::Ethernet;
};

}  // namespace tpi
