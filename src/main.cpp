// tui-packet-inspector - capture engine front-end.
// Captures packets from a live socket, a pcap file or the virtual demo stream and
// prints a short hex preview of every frame.

#include "NetworkSniffer.hpp"
#include "PacketBuffer.hpp"

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

volatile std::sig_atomic_t g_stopRequested = 0;

extern "C" void handleSignal(int) { g_stopRequested = 1; }

struct Options {
    enum class Source { Demo, Live, Pcap } source = Source::Demo;
    std::string interfaceName;
    std::string pcapPath;
    std::string writePath;
    bool realtime = false;
    double rate = 300.0;
    std::uint64_t count = 0;
};

void printUsage() {
    std::puts(
        "Usage: tui-packet-inspector [options]\n"
        "  -d, --demo             virtual traffic stream (default, no privileges needed)\n"
        "  -i, --iface <name>     live capture (Linux: eth0, Windows: local IPv4 address)\n"
        "  -r, --read <file>      read packets from a .pcap file\n"
        "      --realtime         replay a pcap file with its original timing\n"
        "  -w, --write <file>     record captured packets to a .pcap file\n"
        "      --rate <pps>       demo stream rate (default 300)\n"
        "  -n, --count <N>        stop after N packets\n"
        "  -h, --help             show this help");
}

Options parseArguments(int argc, char** argv) {
    Options options;
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
        } else if (arg == "-r" || arg == "--read") {
            options.source = Options::Source::Pcap;
            options.pcapPath = value();
        } else if (arg == "--realtime") {
            options.realtime = true;
        } else if (arg == "-w" || arg == "--write") {
            options.writePath = value();
        } else if (arg == "--rate") {
            options.rate = std::stod(value());
        } else if (arg == "-n" || arg == "--count") {
            options.count = std::stoull(value());
        } else if (arg == "-h" || arg == "--help") {
            printUsage();
            std::exit(EXIT_SUCCESS);
        } else {
            throw std::invalid_argument("unknown option: " + arg);
        }
    }
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
    return tpi::openSyntheticSource(synthetic);
}

void printPacket(std::uint64_t index, const tpi::RawPacket& packet) {
    std::printf("#%-6llu %5u bytes  ", static_cast<unsigned long long>(index), packet.originalLength);
    const std::size_t preview = std::min<std::size_t>(packet.bytes.size(), 24);
    for (std::size_t i = 0; i < preview; ++i) {
        std::printf("%02x ", packet.bytes[i]);
    }
    std::printf("%s\n", packet.bytes.size() > preview ? "..." : "");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parseArguments(argc, argv);
        std::signal(SIGINT, handleSignal);
        std::signal(SIGTERM, handleSignal);

        tpi::PacketBuffer buffer(65536);
        tpi::NetworkSniffer sniffer(openSource(options), buffer);
        if (!options.writePath.empty()) {
            sniffer.setRecorder(std::make_unique<tpi::PcapWriter>(options.writePath));
        }
        std::fprintf(stderr, "capturing from %s (Ctrl+C to stop)\n", sniffer.description().c_str());
        sniffer.start();

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
            buffer.drain(batch, 1024);
            for (const auto& packet : batch) {
                printPacket(++printed, packet);
                if (options.count != 0 && printed >= options.count) {
                    g_stopRequested = 1;
                    break;
                }
            }
        }
        sniffer.stop();
        if (const std::string error = sniffer.lastError(); !error.empty()) {
            std::fprintf(stderr, "capture error: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        std::fprintf(stderr, "%llu packets captured, %llu dropped\n",
                     static_cast<unsigned long long>(sniffer.capturedPackets()),
                     static_cast<unsigned long long>(buffer.droppedCount()));
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return EXIT_FAILURE;
    }
}
