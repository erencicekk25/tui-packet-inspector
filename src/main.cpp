// tui-packet-inspector - command line front-end.
// Captures packets from a live socket, a pcap file or the virtual demo stream, decodes
// them (Ethernet / IPv4 / IPv6 / TCP / UDP / Modbus) and prints one line per packet.

#include "NetworkSniffer.hpp"
#include "PacketBuffer.hpp"
#include "ProtocolDecoder.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
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
    std::vector<std::uint16_t> modbusPorts{502};
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
        "      --modbus-port <p>  extra TCP/UDP port to decode as Modbus (repeatable)\n"
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
        } else if (arg == "--modbus-port") {
            const unsigned long port = std::stoul(value());
            if (port == 0 || port > 65535) {
                throw std::invalid_argument("invalid Modbus port: " + std::to_string(port));
            }
            options.modbusPorts.push_back(static_cast<std::uint16_t>(port));
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

std::string formatTime(tpi::Clock::time_point timestamp) {
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

void printPacket(std::uint64_t index, const tpi::DecodedPacket& packet) {
    std::printf("%-7llu %s  %-6s %-24s -> %-24s %5zu  %s\n", static_cast<unsigned long long>(index),
                formatTime(packet.timestamp).c_str(), tpi::protocolName(packet.protocol), packet.source().c_str(),
                packet.destination().c_str(), packet.wireLength, packet.summary().c_str());
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
                printPacket(++printed, decoder.decode(packet));
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
