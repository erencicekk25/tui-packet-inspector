#pragma once

#include "ProtocolDecoder.hpp"
#include "Terminal.hpp"
#include "TrafficStats.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>

namespace tpi {

/// Compact, render-ready copy of a decoded packet kept in the scroll-back log.
struct LogEntry {
    std::uint64_t number = 0;
    Clock::time_point timestamp{};
    Protocol protocol = Protocol::Unknown;
    std::string source;
    std::string destination;
    std::string info;
    std::size_t length = 0;
    bool malformed = false;
    bool modbusException = false;
};

[[nodiscard]] LogEntry makeLogEntry(std::uint64_t number, const DecodedPacket& packet);

enum class LogFilter : std::uint8_t { All, Tcp, Udp, Modbus, Other };

[[nodiscard]] const char* logFilterName(LogFilter filter) noexcept;
[[nodiscard]] LogFilter nextLogFilter(LogFilter filter) noexcept;
[[nodiscard]] bool logFilterMatches(LogFilter filter, const LogEntry& entry) noexcept;

/// Everything the dashboard shows that is not a traffic statistic.
struct DashboardState {
    std::string sourceDescription;
    std::string modbusPorts = "502";
    bool paused = false;
    bool captureFinished = false;
    std::string captureError;
    std::uint64_t droppedPackets = 0;
    LogFilter filter = LogFilter::All;
    std::size_t scrollOffset = 0;  ///< Log entries hidden below the view (0 = follow newest)
    bool showHelp = false;
    std::chrono::steady_clock::duration uptime{};
};

struct RenderOptions {
    bool color = true;    ///< 256-color ANSI styling
    bool unicode = true;  ///< Box drawing + block glyphs (falls back to plain ASCII)
};

/// Lightweight, dependency-free terminal dashboard built on ANSI escape sequences.
///
/// Each frame is composed off-screen on a cell canvas and flushed with a single write
/// (wrapped in a synchronized-update sequence), so redraws are flicker-free.
class TuiRenderer {
public:
    explicit TuiRenderer(RenderOptions options);

    TuiRenderer(const TuiRenderer&) = delete;
    TuiRenderer& operator=(const TuiRenderer&) = delete;

    void draw(const TrafficStats& stats, const std::deque<LogEntry>& log, const DashboardState& state);
    std::optional<KeyEvent> pollInput(std::chrono::milliseconds timeout);
    [[nodiscard]] TerminalSize size() const { return terminal_.size(); }

    /// Pure function that renders one frame to an ANSI string (used by draw() and the tests).
    [[nodiscard]] static std::string renderFrame(const TrafficStats& stats, const std::deque<LogEntry>& log,
                                                 const DashboardState& state, TerminalSize size,
                                                 RenderOptions options);

private:
    RenderOptions options_;
    Terminal terminal_;  // RAII: restores the user's terminal when the renderer goes away
    TerminalSize lastSize_{0, 0};
};

}  // namespace tpi
