// tui-packet-inspector - entry point.
//
// Wires the three layers together:
//   NetworkSniffer (capture thread) -> PacketBuffer -> ProtocolDecoder -> TrafficStats / log
//   -> TuiRenderer (interactive dashboard) or a plain line-per-packet printer.

#include "NetworkSniffer.hpp"
#include "PacketBuffer.hpp"
#include "ProtocolDecoder.hpp"
#include "Terminal.hpp"
#include "TrafficStats.hpp"
#include "TuiRenderer.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using SteadyClock = std::chrono::steady_clock;

volatile std::sig_atomic_t g_stopRequested = 0;

extern "C" void handleSignal(int) { g_stopRequested = 1; }

constexpr std::size_t kBufferCapacity = 65536;
constexpr std::size_t kLogCapacity = 5000;
constexpr std::size_t kDrainBatch = 8192;

struct Options {
    enum class Source { Demo, Live, Pcap } source = Source::Demo;
    enum class Mode { Auto, Dashboard, Plain } mode = Mode::Auto;
    std::string interfaceName;
    std::string pcapPath;
    std::string writePath;
    bool realtime = false;
    double rate = 300.0;
    std::uint32_t seed = 0;
    std::uint64_t count = 0;
    int fps = 12;
    bool color = true;
    bool unicode = true;
    std::vector<std::uint16_t> modbusPorts{502};
};

void printUsage() {
    std::puts(
        "tui-packet-inspector " TPI_VERSION " - terminal packet inspector for TCP, UDP and Modbus\n"
        "\n"
        "Usage: tui-packet-inspector [source] [options]\n"
        "\n"
        "Sources (default: --demo)\n"
        "  -d, --demo               virtual traffic stream incl. Modbus/TCP + RTU (no privileges)\n"
        "  -i, --iface <name>       live capture  (Linux: eth0 | Windows: local IPv4 address)\n"
        "                           use \"any\" on Linux to listen on all interfaces\n"
        "  -r, --read <file.pcap>   read a classic libpcap file\n"
        "      --realtime           replay a pcap file with its original timing\n"
        "\n"
        "Options\n"
        "  -w, --write <file.pcap>  record every captured packet to a pcap file\n"
        "  -m, --modbus-port <port> extra TCP/UDP port to decode as Modbus (repeatable)\n"
        "      --rate <pps>         demo stream average rate (default 300)\n"
        "      --seed <n>           make the demo stream reproducible\n"
        "  -p, --plain              no dashboard: print one line per packet (auto when piped)\n"
        "  -n, --count <N>          plain mode: stop after N packets\n"
        "      --fps <n>            dashboard refresh rate, 1-60 (default 12)\n"
        "      --no-color           monochrome output (also honors NO_COLOR)\n"
        "      --ascii              ASCII-only glyphs for limited terminals/fonts\n"
        "  -V, --version            print version\n"
        "  -h, --help               show this help\n"
        "\n"
        "Examples\n"
        "  tui-packet-inspector                         # instant demo dashboard\n"
        "  sudo tui-packet-inspector -i eth0 -w out.pcap\n"
        "  tui-packet-inspector -r plant.pcap --realtime -m 5020\n"
        "  tui-packet-inspector -r plant.pcap --plain | grep EXCEPTION");
}

Options parseArguments(int argc, char** argv) {
    Options options;
    if (const char* noColor = std::getenv("NO_COLOR"); noColor != nullptr && noColor[0] != '\0') {
        options.color = false;
    }
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) {
                throw std::invalid_argument("missing value for " + arg);
            }
            return argv[++i];
        };
        if (arg == "-d" || arg == "--demo") {
            options.source = Options::Source::Demo;
        } else if (arg == "-i" || arg == "--iface") {
            options.source = Options::Source::Live;
            options.interfaceName = value();
            if (options.interfaceName == "any") {
                options.interfaceName.clear();
            }
        } else if (arg == "-r" || arg == "--read") {
            options.source = Options::Source::Pcap;
            options.pcapPath = value();
        } else if (arg == "--realtime") {
            options.realtime = true;
        } else if (arg == "-w" || arg == "--write") {
            options.writePath = value();
        } else if (arg == "-m" || arg == "--modbus-port") {
            const unsigned long port = std::stoul(value());
            if (port == 0 || port > 65535) {
                throw std::invalid_argument("invalid Modbus port: " + std::to_string(port));
            }
            options.modbusPorts.push_back(static_cast<std::uint16_t>(port));
        } else if (arg == "--rate") {
            options.rate = std::stod(value());
        } else if (arg == "--seed") {
            options.seed = static_cast<std::uint32_t>(std::stoul(value()));
        } else if (arg == "-p" || arg == "--plain") {
            options.mode = Options::Mode::Plain;
        } else if (arg == "--tui") {
            options.mode = Options::Mode::Dashboard;
        } else if (arg == "-n" || arg == "--count") {
            options.count = std::stoull(value());
        } else if (arg == "--fps") {
            options.fps = std::clamp(std::stoi(value()), 1, 60);
        } else if (arg == "--no-color") {
            options.color = false;
        } else if (arg == "--ascii") {
            options.unicode = false;
        } else if (arg == "-V" || arg == "--version") {
            std::puts("tui-packet-inspector " TPI_VERSION);
            std::exit(EXIT_SUCCESS);
        } else if (arg == "-h" || arg == "--help") {
            printUsage();
            std::exit(EXIT_SUCCESS);
        } else {
            throw std::invalid_argument("unknown option: " + arg + " (see --help)");
        }
    }
    std::sort(options.modbusPorts.begin(), options.modbusPorts.end());
    options.modbusPorts.erase(std::unique(options.modbusPorts.begin(), options.modbusPorts.end()),
                              options.modbusPorts.end());
    return options;
}

std::unique_ptr<tpi::CaptureSource> openSource(const Options& options) {
    switch (options.source) {
        case Options::Source::Live: return tpi::openLiveSource(options.interfaceName);
        case Options::Source::Pcap: return tpi::openPcapFile(options.pcapPath, options.realtime);
        case Options::Source::Demo: break;
    }
    tpi::SyntheticOptions synthetic;
    synthetic.packetsPerSecond = options.rate;
    synthetic.seed = options.seed;
    synthetic.modbusPort = options.modbusPorts.front();
    return tpi::openSyntheticSource(synthetic);
}

std::string joinPorts(const std::vector<std::uint16_t>& ports) {
    std::string text;
    for (const std::uint16_t port : ports) {
        text += (text.empty() ? "" : ", ") + std::to_string(port);
    }
    return text;
}

// ---------------------------------------------------------------------------
// Plain (line-per-packet) mode
// ---------------------------------------------------------------------------

std::string formatTimestamp(tpi::Clock::time_point timestamp) {
    const auto sinceEpoch = timestamp.time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(sinceEpoch);
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(sinceEpoch - seconds).count();
    const auto time = static_cast<std::time_t>(seconds.count());
    std::tm local{};
#if defined(_WIN32)
    localtime_s(&local, &time);
#else
    localtime_r(&time, &local);
#endif
    char text[32];
    std::snprintf(text, sizeof text, "%02d:%02d:%02d.%06ld", local.tm_hour, local.tm_min, local.tm_sec,
                  static_cast<long>(micros));
    return text;
}

void runPlain(const Options& options, tpi::PacketBuffer& buffer, const tpi::ProtocolDecoder& decoder) {
    std::vector<tpi::RawPacket> batch;
    std::uint64_t printed = 0;
    while (g_stopRequested == 0) {
        if (!buffer.waitForData(std::chrono::milliseconds(200))) {
            if (buffer.closed()) {
                break;
            }
            continue;
        }
        batch.clear();
        buffer.drain(batch, kDrainBatch);
        for (const auto& raw : batch) {
            const tpi::DecodedPacket packet = decoder.decode(raw);
            std::printf("%-7llu %s  %-6s %-24s -> %-24s %5zu  %s\n", static_cast<unsigned long long>(++printed),
                        formatTimestamp(packet.timestamp).c_str(), tpi::protocolName(packet.protocol),
                        packet.source().c_str(), packet.destination().c_str(), packet.wireLength,
                        packet.summary().c_str());
            if (options.count != 0 && printed >= options.count) {
                g_stopRequested = 1;
                break;
            }
        }
        std::fflush(stdout);
    }
}

// ---------------------------------------------------------------------------
// Interactive dashboard
// ---------------------------------------------------------------------------

/// Applies a key press to the dashboard state. Returns false when the user wants to quit.
bool handleKey(const tpi::KeyEvent& key, tpi::DashboardState& state, tpi::TrafficStats& stats,
               std::deque<tpi::LogEntry>& log, int pageSize) {
    using Code = tpi::KeyEvent::Code;
    const auto page = static_cast<std::size_t>(std::max(pageSize, 1));
    switch (key.code) {
        case Code::Interrupt: return false;
        case Code::Escape:
            if (state.showHelp) {
                state.showHelp = false;
                return true;
            }
            return false;
        case Code::Up: state.scrollOffset += 1; break;
        case Code::Down: state.scrollOffset -= std::min<std::size_t>(state.scrollOffset, 1); break;
        case Code::PageUp: state.scrollOffset += page; break;
        case Code::PageDown: state.scrollOffset -= std::min(state.scrollOffset, page); break;
        case Code::Home: state.scrollOffset = log.size(); break;
        case Code::End: state.scrollOffset = 0; break;
        case Code::Enter: break;
        case Code::Character:
            switch (key.character) {
                case 'q':
                case 'Q': return false;
                case 'p':
                case 'P':
                case ' ': state.paused = !state.paused; break;
                case 'f':
                case 'F':
                    state.filter = tpi::nextLogFilter(state.filter);
                    state.scrollOffset = 0;
                    break;
                case 'c':
                case 'C':
                    stats.reset();
                    log.clear();
                    state.scrollOffset = 0;
                    break;
                case 'h':
                case 'H':
                case '?': state.showHelp = !state.showHelp; break;
                case 'k': state.scrollOffset += 1; break;
                case 'j': state.scrollOffset -= std::min<std::size_t>(state.scrollOffset, 1); break;
                case 'g': state.scrollOffset = log.size(); break;
                case 'G': state.scrollOffset = 0; break;
                default: break;
            }
            break;
    }
    state.scrollOffset = std::min(state.scrollOffset, log.size());
    return true;
}

void runDashboard(const Options& options, const tpi::NetworkSniffer& sniffer, tpi::PacketBuffer& buffer,
                  const tpi::ProtocolDecoder& decoder) {
    tpi::TuiRenderer renderer(tpi::RenderOptions{options.color, options.unicode});
    tpi::TrafficStats stats;
    std::deque<tpi::LogEntry> log;
    tpi::DashboardState state;
    state.sourceDescription = sniffer.description();
    state.modbusPorts = joinPorts(options.modbusPorts);

    const auto frameInterval = std::chrono::milliseconds(1000 / options.fps);
    const auto started = SteadyClock::now();
    auto nextFrame = started;
    std::vector<tpi::RawPacket> batch;
    batch.reserve(kDrainBatch);
    std::uint64_t packetNumber = 0;

    while (g_stopRequested == 0) {
        batch.clear();
        buffer.drain(batch, kDrainBatch);
        for (const auto& raw : batch) {
            const tpi::DecodedPacket packet = decoder.decode(raw);
            stats.record(packet);
            ++packetNumber;
            if (state.paused) {
                continue;
            }
            log.push_back(tpi::makeLogEntry(packetNumber, packet));
            if (state.scrollOffset > 0 && tpi::logFilterMatches(state.filter, log.back())) {
                ++state.scrollOffset;  // keep a scrolled-back view anchored while new packets arrive
            }
            if (log.size() > kLogCapacity) {
                log.pop_front();
            }
        }

        const auto now = SteadyClock::now();
        stats.advance(now);
        if (now >= nextFrame) {
            state.uptime = now - started;
            state.captureFinished = sniffer.finished();
            state.captureError = sniffer.lastError();
            state.droppedPackets = buffer.droppedCount();
            state.scrollOffset = std::min(state.scrollOffset, log.size());
            renderer.draw(stats, log, state);
            nextFrame = now + frameInterval;
        }

        // Sleep in the key poll until the next frame is due (bounded so packets keep flowing).
        const auto untilFrame = std::chrono::duration_cast<std::chrono::milliseconds>(nextFrame - SteadyClock::now());
        const auto wait = std::clamp(untilFrame, std::chrono::milliseconds(0), std::chrono::milliseconds(50));
        if (const auto key = renderer.pollInput(wait)) {
            const int pageSize = renderer.size().rows / 3;
            if (!handleKey(*key, state, stats, log, pageSize)) {
                break;
            }
            nextFrame = SteadyClock::now();  // redraw immediately for snappy feedback
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parseArguments(argc, argv);
        std::signal(SIGINT, handleSignal);
        std::signal(SIGTERM, handleSignal);

        tpi::DecoderOptions decoderOptions;
        decoderOptions.modbusPorts = options.modbusPorts;
        const tpi::ProtocolDecoder decoder(decoderOptions);

        tpi::PacketBuffer buffer(kBufferCapacity);
        tpi::NetworkSniffer sniffer(openSource(options), buffer);
        if (!options.writePath.empty()) {
            sniffer.setRecorder(std::make_unique<tpi::PcapWriter>(options.writePath));
        }

        const bool dashboard = options.mode == Options::Mode::Dashboard ||
                               (options.mode == Options::Mode::Auto && options.count == 0 &&
                                tpi::Terminal::isInteractive());
        if (!dashboard) {
            std::fprintf(stderr, "capturing from %s (Ctrl+C to stop)\n", sniffer.description().c_str());
        }

        sniffer.start();
        if (dashboard) {
            runDashboard(options, sniffer, buffer, decoder);  // terminal is restored when this returns
        } else {
            runPlain(options, buffer, decoder);
        }
        sniffer.stop();

        if (const std::string error = sniffer.lastError(); !error.empty()) {
            std::fprintf(stderr, "capture error: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        std::fprintf(stderr, "%llu packets captured, %llu dropped by the ring buffer\n",
                     static_cast<unsigned long long>(sniffer.capturedPackets()),
                     static_cast<unsigned long long>(buffer.droppedCount()));
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return EXIT_FAILURE;
    }
}
