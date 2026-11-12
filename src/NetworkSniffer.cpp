#include "NetworkSniffer.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#include <cerrno>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tpi {

// ---------------------------------------------------------------------------
// NetworkSniffer
// ---------------------------------------------------------------------------

NetworkSniffer::NetworkSniffer(std::unique_ptr<CaptureSource> source, PacketBuffer& buffer)
    : source_(std::move(source)), buffer_(buffer) {
    if (!source_) {
        throw CaptureError("NetworkSniffer requires a capture source");
    }
    description_ = source_->description();
}

NetworkSniffer::~NetworkSniffer() { stop(); }

void NetworkSniffer::setRecorder(std::unique_ptr<PcapWriter> recorder) {
    if (!worker_.joinable()) {
        recorder_ = std::move(recorder);
    }
}

void NetworkSniffer::start() {
    if (worker_.joinable()) {
        return;
    }
    stopRequested_ = false;
    running_ = true;
    worker_ = std::thread(&NetworkSniffer::run, this);
}

void NetworkSniffer::stop() {
    stopRequested_ = true;
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::string NetworkSniffer::lastError() const {
    std::lock_guard<std::mutex> lock(errorMutex_);
    return lastError_;
}

void NetworkSniffer::run() {
    constexpr std::chrono::milliseconds kPollInterval{100};
    RawPacket packet;
    while (!stopRequested_) {
        ReadStatus status = ReadStatus::Timeout;
        try {
            status = source_->read(packet, kPollInterval);
        } catch (const std::exception& error) {
            std::lock_guard<std::mutex> lock(errorMutex_);
            lastError_ = error.what();
            status = ReadStatus::EndOfStream;
        }

        if (status == ReadStatus::EndOfStream) {
            finished_ = true;
            break;
        }
        if (status == ReadStatus::Timeout) {
            continue;
        }

        packets_.fetch_add(1, std::memory_order_relaxed);
        bytes_.fetch_add(packet.originalLength, std::memory_order_relaxed);
        if (recorder_) {
            recorder_->write(packet);
        }
        buffer_.push(std::move(packet));
        packet = RawPacket{};
    }
    buffer_.close();
    running_ = false;
}

// ---------------------------------------------------------------------------
// Live capture back-ends
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kSnapLength = 65536;

#if defined(_WIN32)

/// RAII guard for the process-wide Winsock initialization.
class WinsockSession {
public:
    WinsockSession() {
        WSADATA data{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &data);
        if (rc != 0) {
            throw CaptureError("WSAStartup failed with code " + std::to_string(rc));
        }
    }
    ~WinsockSession() { WSACleanup(); }
    WinsockSession(const WinsockSession&) = delete;
    WinsockSession& operator=(const WinsockSession&) = delete;
};

/// RAII owner of a SOCKET handle.
class UniqueSocket {
public:
    explicit UniqueSocket(SOCKET handle = INVALID_SOCKET) noexcept : handle_(handle) {}
    ~UniqueSocket() { reset(); }
    UniqueSocket(const UniqueSocket&) = delete;
    UniqueSocket& operator=(const UniqueSocket&) = delete;

    void reset(SOCKET handle = INVALID_SOCKET) noexcept {
        if (handle_ != INVALID_SOCKET) {
            closesocket(handle_);
        }
        handle_ = handle;
    }
    [[nodiscard]] SOCKET get() const noexcept { return handle_; }
    [[nodiscard]] bool valid() const noexcept { return handle_ != INVALID_SOCKET; }

private:
    SOCKET handle_;
};

std::string winsockError(const char* what) {
    const int code = WSAGetLastError();
    std::string message = std::string(what) + " failed (WSA error " + std::to_string(code) + ")";
    if (code == WSAEACCES) {
        message += ": raw sockets require an elevated (Administrator) terminal";
    }
    return message;
}

in_addr resolveLocalAddress(const std::string& interfaceName) {
    in_addr address{};
    if (!interfaceName.empty()) {
        if (inet_pton(AF_INET, interfaceName.c_str(), &address) != 1) {
            throw CaptureError("on Windows --iface expects a local IPv4 address, e.g. 192.168.1.20");
        }
        return address;
    }

    std::array<char, 256> host{};
    if (gethostname(host.data(), static_cast<int>(host.size())) != 0) {
        throw CaptureError(winsockError("gethostname"));
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* raw = nullptr;
    if (getaddrinfo(host.data(), nullptr, &hints, &raw) != 0 || raw == nullptr) {
        throw CaptureError("cannot resolve local addresses; pass --iface <local-ipv4>");
    }
    const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> results(raw, &freeaddrinfo);
    for (const addrinfo* entry = results.get(); entry != nullptr; entry = entry->ai_next) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
        if ((ntohl(ipv4->sin_addr.s_addr) >> 24) != 127) {
            return ipv4->sin_addr;
        }
    }
    throw CaptureError("no non-loopback IPv4 address found; pass --iface <local-ipv4>");
}

/// Windows raw socket in promiscuous "receive all" mode. Delivers raw IP datagrams.
class WindowsRawSource final : public CaptureSource {
public:
    explicit WindowsRawSource(const std::string& interfaceName) : buffer_(kSnapLength) {
        const in_addr local = resolveLocalAddress(interfaceName);
        std::array<char, INET_ADDRSTRLEN> text{};
        inet_ntop(AF_INET, &local, text.data(), text.size());
        description_ = std::string("live:") + text.data() + " (raw IP, SIO_RCVALL)";

        socket_.reset(::socket(AF_INET, SOCK_RAW, IPPROTO_IP));
        if (!socket_.valid()) {
            throw CaptureError(winsockError("socket(SOCK_RAW)"));
        }
        sockaddr_in bindAddress{};
        bindAddress.sin_family = AF_INET;
        bindAddress.sin_addr = local;
        if (::bind(socket_.get(), reinterpret_cast<const sockaddr*>(&bindAddress), sizeof bindAddress) ==
            SOCKET_ERROR) {
            throw CaptureError(winsockError("bind"));
        }
        DWORD enable = RCVALL_ON;
        DWORD returned = 0;
        if (WSAIoctl(socket_.get(), SIO_RCVALL, &enable, sizeof enable, nullptr, 0, &returned, nullptr,
                     nullptr) == SOCKET_ERROR) {
            throw CaptureError(winsockError("WSAIoctl(SIO_RCVALL)"));
        }
    }

    ReadStatus read(RawPacket& out, std::chrono::milliseconds timeout) override {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(socket_.get(), &readable);
        timeval tv{};
        tv.tv_sec = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
        const int ready = ::select(0, &readable, nullptr, nullptr, &tv);
        if (ready == 0) {
            return ReadStatus::Timeout;
        }
        if (ready == SOCKET_ERROR) {
            throw CaptureError(winsockError("select"));
        }
        int received = ::recv(socket_.get(), reinterpret_cast<char*>(buffer_.data()),
                              static_cast<int>(buffer_.size()), 0);
        if (received == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEMSGSIZE) {
                throw CaptureError(winsockError("recv"));
            }
            received = static_cast<int>(buffer_.size());
        }
        out.bytes.assign(buffer_.begin(), buffer_.begin() + received);
        out.originalLength = static_cast<std::uint32_t>(received);
        out.timestamp = Clock::now();
        out.linkType = LinkType::RawIp;
        return ReadStatus::Packet;
    }

    [[nodiscard]] std::string description() const override { return description_; }

private:
    WinsockSession session_;  // must outlive socket_ (members are destroyed in reverse order)
    UniqueSocket socket_;
    std::vector<std::uint8_t> buffer_;
    std::string description_;
};

#elif defined(__linux__)

/// RAII owner of a POSIX file descriptor.
class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
    ~UniqueFd() { reset(); }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }
    [[nodiscard]] int get() const noexcept { return fd_; }

private:
    int fd_;
};

std::string errnoMessage(const char* what) {
    const int code = errno;
    std::string message = std::string(what) + " failed: " + std::strerror(code);
    if (code == EPERM || code == EACCES) {
        message += " (run as root or grant CAP_NET_RAW: sudo setcap cap_net_raw+ep <binary>)";
    }
    return message;
}

/// Linux AF_PACKET socket. Delivers complete Ethernet frames from one or all interfaces.
class LinuxPacketSource final : public CaptureSource {
public:
    explicit LinuxPacketSource(const std::string& interfaceName) : buffer_(kSnapLength) {
        fd_.reset(::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));
        if (fd_.get() < 0) {
            throw CaptureError(errnoMessage("socket(AF_PACKET)"));
        }
        description_ = "live:" + (interfaceName.empty() ? std::string("any") : interfaceName) + " (AF_PACKET)";
        if (!interfaceName.empty()) {
            const unsigned index = if_nametoindex(interfaceName.c_str());
            if (index == 0) {
                throw CaptureError("unknown network interface: " + interfaceName);
            }
            sockaddr_ll address{};
            address.sll_family = AF_PACKET;
            address.sll_protocol = htons(ETH_P_ALL);
            address.sll_ifindex = static_cast<int>(index);
            if (::bind(fd_.get(), reinterpret_cast<const sockaddr*>(&address), sizeof address) < 0) {
                throw CaptureError(errnoMessage("bind"));
            }
        }
    }

    ReadStatus read(RawPacket& out, std::chrono::milliseconds timeout) override {
        pollfd descriptor{fd_.get(), POLLIN, 0};
        const int ready = ::poll(&descriptor, 1, static_cast<int>(timeout.count()));
        if (ready == 0 || (ready < 0 && errno == EINTR)) {
            return ReadStatus::Timeout;
        }
        if (ready < 0) {
            throw CaptureError(errnoMessage("poll"));
        }
        // MSG_TRUNC makes recv() report the real frame length even if it exceeds our buffer.
        const ssize_t length = ::recv(fd_.get(), buffer_.data(), buffer_.size(), MSG_TRUNC);
        if (length < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                return ReadStatus::Timeout;
            }
            throw CaptureError(errnoMessage("recv"));
        }
        const std::size_t captured = std::min(static_cast<std::size_t>(length), buffer_.size());
        out.bytes.assign(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(captured));
        out.originalLength = static_cast<std::uint32_t>(length);
        out.timestamp = Clock::now();
        out.linkType = LinkType::Ethernet;
        return ReadStatus::Packet;
    }

    [[nodiscard]] std::string description() const override { return description_; }

private:
    UniqueFd fd_;
    std::vector<std::uint8_t> buffer_;
    std::string description_;
};

#endif

}  // namespace

std::unique_ptr<CaptureSource> openLiveSource(const std::string& interfaceName) {
#if defined(_WIN32)
    return std::make_unique<WindowsRawSource>(interfaceName);
#elif defined(__linux__)
    return std::make_unique<LinuxPacketSource>(interfaceName);
#else
    (void)interfaceName;
    throw CaptureError("live capture is not supported on this platform yet; use --read <file.pcap> or --demo");
#endif
}

}  // namespace tpi
