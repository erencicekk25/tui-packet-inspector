#include "TuiRenderer.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <string_view>
#include <utility>
#include <vector>

#ifndef TPI_VERSION
#define TPI_VERSION "dev"
#endif

namespace tpi {
namespace {

// ---------------------------------------------------------------------------
// Styles & glyphs
// ---------------------------------------------------------------------------

enum class Style : std::uint8_t {
    Normal, Dim, Bold, Border, Title,
    Header, HeaderDim, HeaderAccent, Live, Paused, Finished, Error,
    Good, Warn, Bad,
    Tcp, Udp, Modbus, Icmp, Arp, Other,
    BarEmpty, Graph1, Graph2, Graph3,
    ColumnHeader, Key, Footer, FooterWarn,
    Count
};

constexpr std::size_t kStyleCount = static_cast<std::size_t>(Style::Count);

// SGR parameters for 256-color terminals.
constexpr std::array<const char*, kStyleCount> kColorStyles = {
    "0",                      // Normal
    "0;38;5;244",             // Dim
    "0;1",                    // Bold
    "0;38;5;239",             // Border
    "0;1;38;5;81",            // Title
    "0;1;38;5;255;48;5;24",   // Header
    "0;38;5;152;48;5;24",     // HeaderDim
    "0;1;38;5;214;48;5;24",   // HeaderAccent
    "0;1;38;5;84;48;5;24",    // Live
    "0;1;38;5;220;48;5;24",   // Paused
    "0;1;38;5;250;48;5;24",   // Finished
    "0;1;38;5;210;48;5;24",   // Error
    "0;38;5;114",             // Good
    "0;38;5;214",             // Warn
    "0;1;38;5;203",           // Bad
    "0;38;5;75",              // Tcp
    "0;38;5;141",             // Udp
    "0;1;38;5;214",           // Modbus
    "0;38;5;150",             // Icmp
    "0;38;5;180",             // Arp
    "0;38;5;246",             // Other
    "0;38;5;237",             // BarEmpty
    "0;38;5;36",              // Graph1
    "0;38;5;44",              // Graph2
    "0;38;5;87",              // Graph3
    "0;1;38;5;252;48;5;237",  // ColumnHeader
    "0;1;38;5;16;48;5;81",    // Key
    "0;38;5;250;48;5;235",    // Footer
    "0;1;38;5;214;48;5;235",  // FooterWarn
};

// Monochrome fallback (--no-color / NO_COLOR): only bold and reverse video.
constexpr std::array<const char*, kStyleCount> kMonoStyles = {
    "0", "0", "0;1", "0", "0;1",
    "0;7", "0;7", "0;7", "0;1;7", "0;1;7", "0;1;7", "0;1;7",
    "0", "0;1", "0;1",
    "0", "0", "0;1", "0", "0", "0",
    "0", "0", "0", "0",
    "0;7", "0;1;7", "0", "0;1",
};

struct Glyphs {
    char32_t horizontal, vertical, topLeft, topRight, bottomLeft, bottomRight;
    std::array<char32_t, 9> levels;  // vertical eighth blocks, empty -> full
    char32_t barFull, barEmpty, axis;
    char32_t live, paused, finished, logo, arrow, ellipsis;
    const char* scrollKeys;
};

constexpr Glyphs kUnicodeGlyphs{
    U'─', U'│', U'╭', U'╮', U'╰', U'╯',
    {U' ', U'▁', U'▂', U'▃', U'▄', U'▅', U'▆', U'▇', U'█'},
    U'█', U'░', U'┤',
    U'●', U'‖', U'■', U'◆', U'→', U'…',
    "↑↓",
};

constexpr Glyphs kAsciiGlyphs{
    U'-', U'|', U'+', U'+', U'+', U'+',
    {U' ', U'.', U'.', U'_', U'_', U'=', U'=', U'#', U'#'},
    U'#', U'.', U'|',
    U'*', U'"', U'#', U'*', U'>', U'~',
    "Up/Dn",
};

// ---------------------------------------------------------------------------
// UTF-8 helpers
// ---------------------------------------------------------------------------

void appendUtf8(std::string& out, char32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

/// Decodes one code point at `index` and advances it. Invalid sequences yield '?'.
char32_t nextCodepoint(std::string_view text, std::size_t& index) {
    const auto lead = static_cast<unsigned char>(text[index]);
    if (lead < 0x80) {
        ++index;
        return lead;
    }
    std::size_t length = 0;
    if ((lead >> 5) == 0x6) {
        length = 2;
    } else if ((lead >> 4) == 0xE) {
        length = 3;
    } else if ((lead >> 3) == 0x1E) {
        length = 4;
    }
    if (length == 0 || index + length > text.size()) {
        ++index;
        return U'?';
    }
    char32_t cp = lead & (0x7Fu >> length);
    for (std::size_t k = 1; k < length; ++k) {
        cp = (cp << 6) | (static_cast<unsigned char>(text[index + k]) & 0x3Fu);
    }
    index += length;
    return cp;
}

int displayWidth(std::string_view text) {
    int width = 0;
    for (std::size_t i = 0; i < text.size();) {
        nextCodepoint(text, i);
        ++width;
    }
    return width;
}

// ---------------------------------------------------------------------------
// Canvas: an off-screen grid of styled cells
// ---------------------------------------------------------------------------

class Canvas {
public:
    Canvas(int width, int height, const Glyphs& glyphs)
        : width_(width), height_(height), glyphs_(glyphs),
          cells_(static_cast<std::size_t>(width) * static_cast<std::size_t>(height)) {}

    [[nodiscard]] int width() const noexcept { return width_; }
    [[nodiscard]] int height() const noexcept { return height_; }
    [[nodiscard]] const Glyphs& glyphs() const noexcept { return glyphs_; }

    void put(int x, int y, char32_t glyph, Style style) {
        if (x < 0 || y < 0 || x >= width_ || y >= height_) {
            return;
        }
        cells_[static_cast<std::size_t>(y) * static_cast<std::size_t>(width_) + static_cast<std::size_t>(x)] =
            Cell{glyph, style};
    }

    /// Writes text, clipped to `maxWidth` columns. Returns the number of columns used.
    int text(int x, int y, std::string_view value, Style style, int maxWidth = INT_MAX) {
        int written = 0;
        for (std::size_t i = 0; i < value.size() && written < maxWidth;) {
            put(x + written, y, nextCodepoint(value, i), style);
            ++written;
        }
        return written;
    }

    /// Writes text into exactly `width` columns: truncated with an ellipsis or padded.
    void fitted(int x, int y, std::string_view value, Style style, int width) {
        if (width <= 0) {
            return;
        }
        const int length = displayWidth(value);
        if (length <= width) {
            text(x, y, value, style);
            fill(x + length, y, width - length, 1, U' ', style);
        } else {
            text(x, y, value, style, width - 1);
            put(x + width - 1, y, glyphs_.ellipsis, Style::Dim);
        }
    }

    void rightAligned(int rightEdge, int y, std::string_view value, Style style) {
        text(rightEdge - displayWidth(value) + 1, y, value, style);
    }

    void fill(int x, int y, int width, int height, char32_t glyph, Style style) {
        for (int row = y; row < y + height; ++row) {
            for (int column = x; column < x + width; ++column) {
                put(column, row, glyph, style);
            }
        }
    }

    void panel(int x, int y, int width, int height, std::string_view title) {
        const Glyphs& g = glyphs_;
        put(x, y, g.topLeft, Style::Border);
        put(x + width - 1, y, g.topRight, Style::Border);
        put(x, y + height - 1, g.bottomLeft, Style::Border);
        put(x + width - 1, y + height - 1, g.bottomRight, Style::Border);
        fill(x + 1, y, width - 2, 1, g.horizontal, Style::Border);
        fill(x + 1, y + height - 1, width - 2, 1, g.horizontal, Style::Border);
        fill(x, y + 1, 1, height - 2, g.vertical, Style::Border);
        fill(x + width - 1, y + 1, 1, height - 2, g.vertical, Style::Border);
        if (!title.empty()) {
            put(x + 2, y, U' ', Style::Title);
            const int used = text(x + 3, y, title, Style::Title, width - 6);
            put(x + 3 + used, y, U' ', Style::Title);
        }
    }

    [[nodiscard]] std::string toAnsi(bool color) const {
        const auto& styles = color ? kColorStyles : kMonoStyles;
        std::string out;
        out.reserve(cells_.size() * 3 + static_cast<std::size_t>(height_) * 16);
        out += "\x1b[?2026h";  // begin synchronized update (ignored by terminals without support)
        for (int y = 0; y < height_; ++y) {
            out += "\x1b[" + std::to_string(y + 1) + ";1H";
            Style current = Style::Count;
            for (int x = 0; x < width_; ++x) {
                const Cell& cell =
                    cells_[static_cast<std::size_t>(y) * static_cast<std::size_t>(width_) + static_cast<std::size_t>(x)];
                if (cell.style != current) {
                    current = cell.style;
                    out += "\x1b[";
                    out += styles[static_cast<std::size_t>(current)];
                    out += 'm';
                }
                appendUtf8(out, cell.glyph);
            }
        }
        out += "\x1b[0m\x1b[?2026l";
        return out;
    }

private:
    struct Cell {
        char32_t glyph = U' ';
        Style style = Style::Normal;
    };

    int width_;
    int height_;
    const Glyphs& glyphs_;
    std::vector<Cell> cells_;
};

/// Appends styled text segments on one row, clipped at `rightEdge` (inclusive).
class LineWriter {
public:
    LineWriter(Canvas& canvas, int x, int y, int rightEdge) : canvas_(canvas), x_(x), y_(y), rightEdge_(rightEdge) {}

    LineWriter& add(std::string_view value, Style style) {
        x_ += canvas_.text(x_, y_, value, style, std::max(0, rightEdge_ - x_ + 1));
        return *this;
    }
    [[nodiscard]] int x() const noexcept { return x_; }

private:
    Canvas& canvas_;
    int x_;
    int y_;
    int rightEdge_;
};

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

std::string withSeparators(std::uint64_t value) {
    std::string text = std::to_string(value);
    for (int i = static_cast<int>(text.size()) - 3; i > 0; i -= 3) {
        text.insert(static_cast<std::size_t>(i), 1, ',');
    }
    return text;
}

std::string humanBytes(double bytes) {
    static constexpr std::array<const char*, 5> kUnits{"B", "KB", "MB", "GB", "TB"};
    std::size_t unit = 0;
    while (bytes >= 1024.0 && unit + 1 < kUnits.size()) {
        bytes /= 1024.0;
        ++unit;
    }
    char text[32];
    std::snprintf(text, sizeof text, unit == 0 ? "%.0f %s" : "%.1f %s", bytes, kUnits[unit]);
    return text;
}

std::string compactNumber(double value) {
    char text[32];
    if (value >= 1e6) {
        std::snprintf(text, sizeof text, "%.1fM", value / 1e6);
    } else if (value >= 1e4) {
        std::snprintf(text, sizeof text, "%.0fk", value / 1e3);
    } else if (value >= 1e3) {
        std::snprintf(text, sizeof text, "%.1fk", value / 1e3);
    } else {
        std::snprintf(text, sizeof text, "%.0f", value);
    }
    return text;
}

std::string formatPercent(double fraction) {
    char text[16];
    std::snprintf(text, sizeof text, "%.1f%%", fraction * 100.0);
    return text;
}

std::string formatMillis(double millis) {
    char text[24];
    std::snprintf(text, sizeof text, millis < 10.0 ? "%.2f ms" : "%.1f ms", millis);
    return text;
}

std::string formatUptime(std::chrono::steady_clock::duration uptime) {
    const auto total = std::chrono::duration_cast<std::chrono::seconds>(uptime).count();
    char text[24];
    std::snprintf(text, sizeof text, "%02lld:%02lld:%02lld", static_cast<long long>(total / 3600),
                  static_cast<long long>((total / 60) % 60), static_cast<long long>(total % 60));
    return text;
}

std::string formatClock(Clock::time_point timestamp) {
    const auto sinceEpoch = timestamp.time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(sinceEpoch);
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(sinceEpoch - seconds).count();
    const auto time = static_cast<std::time_t>(seconds.count());
    std::tm local{};
#if defined(_WIN32)
    localtime_s(&local, &time);
#else
    localtime_r(&time, &local);
#endif
    char text[24];
    std::snprintf(text, sizeof text, "%02d:%02d:%02d.%03d", local.tm_hour, local.tm_min, local.tm_sec,
                  static_cast<int>(millis));
    return text;
}

double niceCeiling(double value) {
    if (value <= 0.0) {
        return 1.0;
    }
    const double magnitude = std::pow(10.0, std::floor(std::log10(value)));
    const double fraction = value / magnitude;
    const double nice = fraction <= 1.0 ? 1.0 : fraction <= 2.0 ? 2.0 : fraction <= 5.0 ? 5.0 : 10.0;
    return nice * magnitude;
}

Style protocolStyle(Protocol protocol) {
    switch (protocol) {
        case Protocol::Tcp: return Style::Tcp;
        case Protocol::Udp: return Style::Udp;
        case Protocol::Modbus: return Style::Modbus;
        case Protocol::Icmp: return Style::Icmp;
        case Protocol::Arp: return Style::Arp;
        default: return Style::Other;
    }
}

void drawBar(Canvas& canvas, int x, int y, int width, double fraction, Style style) {
    const int filled = std::clamp(static_cast<int>(std::lround(fraction * width)), fraction > 0.0 ? 1 : 0, width);
    canvas.fill(x, y, filled, 1, canvas.glyphs().barFull, style);
    canvas.fill(x + filled, y, width - filled, 1, canvas.glyphs().barEmpty, Style::BarEmpty);
}

// ---------------------------------------------------------------------------
// Panels
// ---------------------------------------------------------------------------

void drawHeader(Canvas& canvas, const DashboardState& state) {
    const Glyphs& g = canvas.glyphs();
    const int width = canvas.width();
    canvas.fill(0, 0, width, 1, U' ', Style::Header);

    // Right side: status badge + uptime
    const std::string uptime = "up " + formatUptime(state.uptime) + " ";
    int right = width - displayWidth(uptime);
    canvas.text(right, 0, uptime, Style::HeaderDim);

    std::string status = "LIVE";
    Style statusStyle = Style::Live;
    char32_t icon = g.live;
    if (!state.captureError.empty()) {
        status = "ERROR";
        statusStyle = Style::Error;
        icon = g.finished;
    } else if (state.captureFinished) {
        status = "FINISHED";
        statusStyle = Style::Finished;
        icon = g.finished;
    } else if (state.paused) {
        status = "PAUSED";
        statusStyle = Style::Paused;
        icon = g.paused;
    }
    right -= displayWidth(status) + 5;
    canvas.put(right, 0, icon, statusStyle);
    canvas.text(right + 2, 0, status, statusStyle);

    // Left side: logo, name, version, source
    int x = 1;
    canvas.put(x, 0, g.logo, Style::HeaderAccent);
    x += 2;
    x += canvas.text(x, 0, "tui-packet-inspector", Style::Header);
    x += 1;
    x += canvas.text(x, 0, "v" TPI_VERSION, Style::HeaderDim);
    x += 3;
    const int available = right - x - 2;
    if (available > 12) {
        x += canvas.text(x, 0, "source ", Style::HeaderDim);
        canvas.fitted(x, 0, state.sourceDescription, Style::Header, available - 7);
    }
}

void drawThroughput(Canvas& canvas, const TrafficStats& stats, int x, int y, int width, int height) {
    canvas.panel(x, y, width, height, "Throughput");
    const Glyphs& g = canvas.glyphs();
    const int innerX = x + 2;
    const int innerWidth = width - 4;
    const int rightEdge = x + width - 3;

    LineWriter line(canvas, innerX, y + 1, rightEdge);
    line.add(compactNumber(stats.packetRate()), Style::Bold)
        .add(" pkt/s   ", Style::Dim)
        .add(humanBytes(stats.byteRate()) + "/s", Style::Bold)
        .add("   peak ", Style::Dim)
        .add(compactNumber(stats.peakPacketRate()), Style::Normal)
        .add(" pkt/s", Style::Dim);
    const std::string totals =
        withSeparators(stats.totalPackets()) + " pkts " + humanBytes(static_cast<double>(stats.totalBytes()));
    if (line.x() + displayWidth(totals) + 3 <= rightEdge) {
        canvas.rightAligned(rightEdge, y + 1, totals, Style::Dim);
    }

    // Multi-row area chart of packets per second, newest sample on the right.
    const int graphTop = y + 2;
    const int graphHeight = height - 3;
    constexpr int kAxisWidth = 6;
    const int graphX = innerX + kAxisWidth;
    const int graphWidth = innerWidth - kAxisWidth;
    if (graphHeight < 1 || graphWidth < 4) {
        return;
    }

    const auto& history = stats.packetRateHistory();
    const std::size_t samples = std::min(history.size(), static_cast<std::size_t>(graphWidth));
    const std::size_t first = history.size() - samples;
    double maximum = 0.0;
    for (std::size_t i = first; i < history.size(); ++i) {
        maximum = std::max(maximum, history[i]);
    }
    const double scale = niceCeiling(std::max(maximum * 1.1, 10.0));

    // Y axis with tick labels at the top, middle and bottom.
    canvas.fill(graphX - 1, graphTop, 1, graphHeight, g.vertical, Style::Border);
    auto tick = [&](int row, const std::string& label) {
        canvas.rightAligned(graphX - 2, row, label, Style::Dim);
        canvas.put(graphX - 1, row, g.axis, Style::Border);
    };
    tick(graphTop, compactNumber(scale));
    if (graphHeight >= 3) {
        tick(graphTop + graphHeight / 2, compactNumber(scale / 2.0));
    }
    tick(graphTop + graphHeight - 1, "0");

    for (std::size_t k = 0; k < samples; ++k) {
        const double value = history[first + k];
        const int column = graphX + graphWidth - static_cast<int>(samples) + static_cast<int>(k);
        const double eighths = value / scale * graphHeight * 8.0;
        for (int row = 0; row < graphHeight; ++row) {
            int level = std::clamp(static_cast<int>(std::lround(eighths - row * 8.0)), 0, 8);
            if (row == 0 && level == 0 && value > 0.0) {
                level = 1;  // keep any non-zero traffic visible
            }
            if (level == 0) {
                continue;
            }
            const double position = static_cast<double>(row + 1) / graphHeight;
            const Style style = position <= 0.34 ? Style::Graph1 : position <= 0.67 ? Style::Graph2 : Style::Graph3;
            canvas.put(column, graphTop + graphHeight - 1 - row, g.levels[static_cast<std::size_t>(level)], style);
        }
    }
}

void drawProtocols(Canvas& canvas, const TrafficStats& stats, int x, int y, int width, int height) {
    canvas.panel(x, y, width, height, "Protocols");
    struct Row {
        const char* name;
        std::uint64_t count;
        Style style;
    };
    const std::array<Row, 6> rows{{
        {"Modbus", stats.protocolCount(Protocol::Modbus), Style::Modbus},
        {"TCP", stats.protocolCount(Protocol::Tcp), Style::Tcp},
        {"UDP", stats.protocolCount(Protocol::Udp), Style::Udp},
        {"ICMP", stats.protocolCount(Protocol::Icmp), Style::Icmp},
        {"ARP", stats.protocolCount(Protocol::Arp), Style::Arp},
        {"Other", stats.protocolCount(Protocol::Unknown) + stats.protocolCount(Protocol::Ipv4) +
                      stats.protocolCount(Protocol::Ipv6),
         Style::Other},
    }};
    const double total = static_cast<double>(std::max<std::uint64_t>(stats.totalPackets(), 1));
    const int innerX = x + 2;
    const int rightEdge = x + width - 3;
    const int barWidth = width - 4 - 7 - 16 - 1;
    int row = y + 1;
    for (const Row& entry : rows) {
        if (row >= y + height - 1) {
            return;
        }
        const double fraction = static_cast<double>(entry.count) / total;
        canvas.text(innerX, row, entry.name, entry.style);
        if (barWidth >= 4) {
            drawBar(canvas, innerX + 7, row, barWidth, fraction, entry.style);
        }
        canvas.rightAligned(rightEdge - 9, row, formatPercent(fraction), Style::Normal);
        canvas.rightAligned(rightEdge, row, withSeparators(entry.count), Style::Dim);
        ++row;
    }
    if (row + 1 < y + height - 1) {
        ++row;
        LineWriter(canvas, innerX, row, rightEdge)
            .add("malformed ", Style::Dim)
            .add(withSeparators(stats.malformedPackets()), stats.malformedPackets() > 0 ? Style::Warn : Style::Normal)
            .add("  syn ", Style::Dim)
            .add(withSeparators(stats.tcpSyns()), Style::Normal)
            .add("  rst ", Style::Dim)
            .add(withSeparators(stats.tcpResets()), stats.tcpResets() > 0 ? Style::Warn : Style::Normal);
    }
}

void drawTalkers(Canvas& canvas, const TrafficStats& stats, int x, int y, int width, int height) {
    canvas.panel(x, y, width, height, "Top talkers");
    const int innerX = x + 2;
    const int innerWidth = width - 4;
    const int rightEdge = x + width - 3;
    const bool showShare = innerWidth >= 44;
    constexpr int kShareBarWidth = 8;
    const int shareWidth = showShare ? kShareBarWidth + 1 : 0;
    const int bytesRight = rightEdge - shareWidth;
    const int packetsRight = bytesRight - 11;
    const int addressWidth = packetsRight - 8 - innerX;

    canvas.text(innerX, y + 1, "Source", Style::Dim);
    canvas.rightAligned(packetsRight, y + 1, "Packets", Style::Dim);
    canvas.rightAligned(bytesRight, y + 1, "Bytes", Style::Dim);
    if (showShare) {
        canvas.text(rightEdge - kShareBarWidth + 1, y + 1, "Share", Style::Dim);
    }

    const int rows = height - 3;
    const auto talkers = stats.topTalkers(static_cast<std::size_t>(std::max(rows, 0)));
    const double total = static_cast<double>(std::max<std::uint64_t>(stats.totalBytes(), 1));
    int row = y + 2;
    for (const TalkerStat& talker : talkers) {
        canvas.fitted(innerX, row, talker.address, Style::Normal, addressWidth);
        canvas.rightAligned(packetsRight, row, withSeparators(talker.packets), Style::Normal);
        canvas.rightAligned(bytesRight, row, humanBytes(static_cast<double>(talker.bytes)), Style::Dim);
        if (showShare) {
            drawBar(canvas, rightEdge - kShareBarWidth + 1, row, kShareBarWidth,
                    static_cast<double>(talker.bytes) / total, Style::Graph2);
        }
        ++row;
    }
    if (talkers.empty()) {
        canvas.text(innerX, y + 2, "No traffic yet.", Style::Dim);
    }
}

void drawModbus(Canvas& canvas, const TrafficStats& stats, const DashboardState& state, int x, int y, int width,
                int height) {
    canvas.panel(x, y, width, height, "Modbus / ICS");
    const ModbusStats& modbus = stats.modbus();
    const int innerX = x + 2;
    const int innerWidth = width - 4;
    const int rightEdge = x + width - 3;
    const int lastRow = y + height - 2;

    std::uint64_t observed = 0;
    for (const std::uint64_t count : modbus.functionCounts) {
        observed += count;
    }
    if (observed == 0) {
        canvas.text(innerX, y + 1, "No Modbus traffic yet.", Style::Dim);
        canvas.fitted(innerX, y + 2, "Watching TCP/UDP port(s): " + state.modbusPorts, Style::Dim, innerWidth);
        canvas.fitted(innerX, y + 3, "Add more with --modbus-port <port>.", Style::Dim, innerWidth);
        return;
    }

    LineWriter counters(canvas, innerX, y + 1, rightEdge);
    counters.add("req ", Style::Dim)
        .add(withSeparators(modbus.requests), Style::Bold)
        .add("  resp ", Style::Dim)
        .add(withSeparators(modbus.responses), Style::Bold)
        .add("  exc ", Style::Dim)
        .add(withSeparators(modbus.exceptions), modbus.exceptions > 0 ? Style::Bad : Style::Good);
    if (modbus.responses > 0) {
        const double ratio = static_cast<double>(modbus.exceptions) / static_cast<double>(modbus.responses);
        counters.add(" (" + formatPercent(ratio) + ")", Style::Dim);
    }

    if (y + 2 <= lastRow) {
        LineWriter(canvas, innerX, y + 2, rightEdge)
            .add("rtt avg ", Style::Dim)
            .add(formatMillis(modbus.averageLatencyMs()), Style::Good)
            .add("  max ", Style::Dim)
            .add(formatMillis(modbus.latencyMaxMs), modbus.latencyMaxMs > 100.0 ? Style::Warn : Style::Normal)
            .add("  last ", Style::Dim)
            .add(formatMillis(modbus.lastLatencyMs), Style::Normal);
    }

    // Function code breakdown, most frequent first.
    std::vector<std::pair<std::uint8_t, std::uint64_t>> functions;
    for (std::size_t code = 0; code < modbus.functionCounts.size(); ++code) {
        if (modbus.functionCounts[code] > 0) {
            functions.emplace_back(static_cast<std::uint8_t>(code), modbus.functionCounts[code]);
        }
    }
    std::sort(functions.begin(), functions.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

    const bool hasException = !modbus.lastException.empty();
    const int functionRowsEnd = hasException ? lastRow - 1 : lastRow;
    const int barWidth = std::min(14, innerWidth - 34);
    int row = y + 3;
    for (const auto& [code, count] : functions) {
        if (row > functionRowsEnd) {
            break;
        }
        char label[8];
        std::snprintf(label, sizeof label, "FC%02u", static_cast<unsigned>(code));
        canvas.text(innerX, row, label, Style::Modbus);
        const int nameWidth = innerWidth - 5 - (barWidth > 3 ? barWidth + 1 : 0) - 7;
        canvas.fitted(innerX + 5, row, modbusFunctionName(code), Style::Normal, nameWidth);
        const double fraction = static_cast<double>(count) / static_cast<double>(observed);
        if (barWidth > 3) {
            drawBar(canvas, rightEdge - 7 - barWidth, row, barWidth, fraction, Style::Modbus);
        }
        canvas.rightAligned(rightEdge, row, formatPercent(fraction), Style::Dim);
        ++row;
    }
    if (hasException) {
        canvas.fitted(innerX, lastRow, "last exc: " + modbus.lastException, Style::Bad, innerWidth);
    }
}

void drawLog(Canvas& canvas, const std::deque<LogEntry>& log, const DashboardState& state, int x, int y, int width,
             int height) {
    const Glyphs& g = canvas.glyphs();
    std::size_t matching = 0;
    for (const LogEntry& entry : log) {
        matching += logFilterMatches(state.filter, entry) ? 1 : 0;
    }
    const std::string title = std::string("Packet log ") + "[" + logFilterName(state.filter) + "] " +
                              withSeparators(matching) + " entries";
    canvas.panel(x, y, width, height, title);

    const int innerX = x + 2;
    const int innerWidth = width - 4;
    const int rows = height - 3;
    const std::size_t maxScroll = matching > static_cast<std::size_t>(rows) ? matching - static_cast<std::size_t>(rows) : 0;
    const std::size_t scroll = std::min(state.scrollOffset, maxScroll);

    // Badge in the top-right border
    std::string badge;
    Style badgeStyle = Style::Title;
    if (state.paused) {
        badge = " PAUSED ";
        badgeStyle = Style::Warn;
    } else if (scroll > 0) {
        badge = " " + withSeparators(scroll) + " newer below ";
        badgeStyle = Style::Warn;
    } else {
        badge = " following ";
        badgeStyle = Style::Good;
    }
    canvas.rightAligned(x + width - 3, y, badge, badgeStyle);

    // Column layout
    constexpr int kNumberWidth = 7;
    constexpr int kTimeWidth = 12;
    constexpr int kProtoWidth = 7;
    constexpr int kLengthWidth = 5;
    const bool showTime = innerWidth >= 100;  // narrow terminals trade the clock for a wider Info column
    const int timeWidth = showTime ? kTimeWidth + 1 : 0;
    const int fixed = kNumberWidth + 1 + timeWidth + kProtoWidth + 1 + 3 + 1 + kLengthWidth + 1;
    const int flexible = innerWidth - fixed;
    const int addressWidth = std::clamp(flexible / 4, 12, 22);
    const int infoWidth = flexible - 2 * addressWidth;

    const int colNumber = innerX;
    const int colTime = colNumber + kNumberWidth + 1;
    const int colProto = colTime + timeWidth;
    const int colSource = colProto + kProtoWidth + 1;
    const int colArrow = colSource + addressWidth;
    const int colDestination = colArrow + 3;
    const int colLength = colDestination + addressWidth + 1;
    const int colInfo = colLength + kLengthWidth + 1;

    const int headerRow = y + 1;
    canvas.fill(x + 1, headerRow, width - 2, 1, U' ', Style::ColumnHeader);
    canvas.text(colNumber, headerRow, "No.", Style::ColumnHeader);
    if (showTime) {
        canvas.text(colTime, headerRow, "Time", Style::ColumnHeader);
    }
    canvas.text(colProto, headerRow, "Proto", Style::ColumnHeader);
    canvas.text(colSource, headerRow, "Source", Style::ColumnHeader);
    canvas.text(colDestination, headerRow, "Destination", Style::ColumnHeader);
    canvas.rightAligned(colLength + kLengthWidth - 1, headerRow, "Len", Style::ColumnHeader);
    canvas.text(colInfo, headerRow, "Info", Style::ColumnHeader);

    int contentTop = y + 2;
    int contentRows = rows;
    if (!state.captureError.empty() && contentRows > 0) {
        canvas.fitted(innerX, contentTop, "capture error: " + state.captureError, Style::Bad, innerWidth);
        ++contentTop;
        --contentRows;
    }
    if (matching == 0) {
        if (contentRows > 0) {
            const std::string waiting =
                log.empty() ? "Waiting for packets..." : "No packets match the current filter (press f).";
            canvas.text(innerX + std::max(0, (innerWidth - displayWidth(waiting)) / 2), contentTop + contentRows / 2,
                        waiting, Style::Dim);
        }
        return;
    }

    // Collect the visible window (newest at the bottom), skipping `scroll` newer entries.
    std::vector<const LogEntry*> visible;
    visible.reserve(static_cast<std::size_t>(std::max(contentRows, 0)));
    std::size_t skipped = 0;
    for (auto it = log.rbegin(); it != log.rend() && static_cast<int>(visible.size()) < contentRows; ++it) {
        if (!logFilterMatches(state.filter, *it)) {
            continue;
        }
        if (skipped < scroll) {
            ++skipped;
            continue;
        }
        visible.push_back(&*it);
    }
    std::reverse(visible.begin(), visible.end());

    int row = contentTop + contentRows - static_cast<int>(visible.size());
    for (const LogEntry* entry : visible) {
        Style infoStyle = Style::Normal;
        if (entry->modbusException) {
            infoStyle = Style::Bad;
        } else if (entry->malformed) {
            infoStyle = Style::Warn;
        } else if (entry->protocol == Protocol::Modbus) {
            infoStyle = Style::Modbus;
        }
        canvas.fitted(colNumber, row, std::to_string(entry->number), Style::Dim, kNumberWidth);
        if (showTime) {
            canvas.text(colTime, row, formatClock(entry->timestamp), Style::Dim);
        }
        canvas.text(colProto, row, protocolName(entry->protocol), protocolStyle(entry->protocol));
        canvas.fitted(colSource, row, entry->source, Style::Normal, addressWidth);
        canvas.put(colArrow + 1, row, g.arrow, Style::Dim);
        canvas.fitted(colDestination, row, entry->destination, Style::Normal, addressWidth);
        canvas.rightAligned(colLength + kLengthWidth - 1, row, std::to_string(entry->length), Style::Dim);
        canvas.fitted(colInfo, row, entry->info, infoStyle, infoWidth);
        ++row;
    }
}

void drawFooter(Canvas& canvas, const DashboardState& state) {
    const int y = canvas.height() - 1;
    canvas.fill(0, y, canvas.width(), 1, U' ', Style::Footer);
    const std::array<std::pair<std::string, std::string>, 7> keys{{
        {"q", "Quit"},
        {"p", state.paused ? "Resume" : "Pause"},
        {"f", std::string("Filter:") + logFilterName(state.filter)},
        {canvas.glyphs().scrollKeys, "Scroll"},
        {"End", "Follow"},
        {"c", "Clear"},
        {"h", "Help"},
    }};
    int x = 1;
    for (const auto& [key, label] : keys) {
        const int needed = displayWidth(key) + displayWidth(label) + 4;
        if (x + needed >= canvas.width() - 1) {
            break;
        }
        x += canvas.text(x, y, " " + key + " ", Style::Key);
        x += canvas.text(x, y, " " + label + " ", Style::Footer);
        x += 1;
    }
    if (state.droppedPackets > 0) {
        const std::string drops = "buffer drops " + withSeparators(state.droppedPackets) + " ";
        if (x + displayWidth(drops) < canvas.width()) {
            canvas.rightAligned(canvas.width() - 1, y, drops, Style::FooterWarn);
        }
    }
}

void drawHelp(Canvas& canvas) {
    static constexpr std::array<std::pair<const char*, const char*>, 9> kLines{{
        {"q  Esc", "quit"},
        {"p  Space", "pause / resume the packet log"},
        {"f", "cycle filter: All > TCP > UDP > Modbus > Other"},
        {"Up/Down  j/k", "scroll one line"},
        {"PgUp/PgDn", "scroll one page"},
        {"Home / End", "jump to oldest / follow newest"},
        {"c", "clear statistics and log"},
        {"h  ?", "toggle this help"},
        {"", "Statistics keep updating while paused."},
    }};
    const int width = std::min(64, canvas.width() - 4);
    const int height = static_cast<int>(kLines.size()) + 4;
    const int x = (canvas.width() - width) / 2;
    const int y = (canvas.height() - height) / 2;
    canvas.fill(x, y, width, height, U' ', Style::Normal);
    canvas.panel(x, y, width, height, "Keyboard shortcuts");
    int row = y + 2;
    for (const auto& [keys, description] : kLines) {
        canvas.text(x + 3, row, keys, Style::Title);
        canvas.fitted(x + 18, row, description, keys[0] == '\0' ? Style::Dim : Style::Normal, width - 21);
        ++row;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

LogEntry makeLogEntry(std::uint64_t number, const DecodedPacket& packet) {
    LogEntry entry;
    entry.number = number;
    entry.timestamp = packet.timestamp;
    entry.protocol = packet.protocol;
    entry.source = packet.source();
    entry.destination = packet.destination();
    entry.info = packet.summary();
    entry.length = packet.wireLength;
    entry.malformed = packet.malformed();
    entry.modbusException = packet.modbus && packet.modbus->isException;
    return entry;
}

const char* logFilterName(LogFilter filter) noexcept {
    switch (filter) {
        case LogFilter::Tcp: return "TCP";
        case LogFilter::Udp: return "UDP";
        case LogFilter::Modbus: return "Modbus";
        case LogFilter::Other: return "Other";
        case LogFilter::All: break;
    }
    return "All";
}

LogFilter nextLogFilter(LogFilter filter) noexcept {
    switch (filter) {
        case LogFilter::All: return LogFilter::Tcp;
        case LogFilter::Tcp: return LogFilter::Udp;
        case LogFilter::Udp: return LogFilter::Modbus;
        case LogFilter::Modbus: return LogFilter::Other;
        case LogFilter::Other: break;
    }
    return LogFilter::All;
}

bool logFilterMatches(LogFilter filter, const LogEntry& entry) noexcept {
    switch (filter) {
        case LogFilter::All: return true;
        case LogFilter::Tcp: return entry.protocol == Protocol::Tcp;
        case LogFilter::Udp: return entry.protocol == Protocol::Udp;
        case LogFilter::Modbus: return entry.protocol == Protocol::Modbus;
        case LogFilter::Other:
            return entry.protocol != Protocol::Tcp && entry.protocol != Protocol::Udp &&
                   entry.protocol != Protocol::Modbus;
    }
    return true;
}

TuiRenderer::TuiRenderer(RenderOptions options) : options_(options) {}

void TuiRenderer::draw(const TrafficStats& stats, const std::deque<LogEntry>& log, const DashboardState& state) {
    const TerminalSize current = terminal_.size();
    std::string frame;
    if (current != lastSize_) {
        frame = "\x1b[0m\x1b[2J";  // full clear after a resize to drop stale cells
        lastSize_ = current;
    }
    frame += renderFrame(stats, log, state, current, options_);
    terminal_.write(frame);
}

std::optional<KeyEvent> TuiRenderer::pollInput(std::chrono::milliseconds timeout) { return terminal_.readKey(timeout); }

std::string TuiRenderer::renderFrame(const TrafficStats& stats, const std::deque<LogEntry>& log,
                                     const DashboardState& state, TerminalSize size, RenderOptions options) {
    constexpr int kMinColumns = 80;
    constexpr int kMinRows = 22;
    const Glyphs& glyphs = options.unicode ? kUnicodeGlyphs : kAsciiGlyphs;
    const int width = std::max(size.columns, 1);
    const int height = std::max(size.rows, 1);
    Canvas canvas(width, height, glyphs);

    if (width < kMinColumns || height < kMinRows) {
        const std::string message = "Terminal too small: " + std::to_string(width) + "x" + std::to_string(height);
        const std::string hint = "need at least " + std::to_string(kMinColumns) + "x" + std::to_string(kMinRows) +
                                 "  (q to quit)";
        canvas.text(std::max(0, (width - displayWidth(message)) / 2), height / 2 - 1, message, Style::Warn);
        canvas.text(std::max(0, (width - displayWidth(hint)) / 2), height / 2, hint, Style::Dim);
        return canvas.toAnsi(options.color);
    }

    const int topHeight = height >= 40 ? 12 : height >= 30 ? 10 : 8;
    const int middleHeight = height >= 34 ? 9 : 7;
    const int logHeight = height - 2 - topHeight - middleHeight;
    const int leftWidth = width * 3 / 5;
    const int rightWidth = width - leftWidth;
    const int middleY = 1 + topHeight;
    const int logY = middleY + middleHeight;

    drawHeader(canvas, state);
    drawThroughput(canvas, stats, 0, 1, leftWidth, topHeight);
    drawProtocols(canvas, stats, leftWidth, 1, rightWidth, topHeight);
    const int talkersWidth = std::max(width * 2 / 5, 40);
    drawTalkers(canvas, stats, 0, middleY, talkersWidth, middleHeight);
    drawModbus(canvas, stats, state, talkersWidth, middleY, width - talkersWidth, middleHeight);
    drawLog(canvas, log, state, 0, logY, width, logHeight);
    drawFooter(canvas, state);
    if (state.showHelp) {
        drawHelp(canvas);
    }
    return canvas.toAnsi(options.color);
}

}  // namespace tpi
