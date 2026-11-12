#pragma once

#include "Packet.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace tpi {

/// Bounded, thread-safe ring buffer that decouples the capture thread from the
/// decoding / rendering thread.
///
/// When the ring is full the *oldest* packet is overwritten, so a slow consumer
/// can never stall the capture loop. Overwrites are counted and reported as drops.
class PacketBuffer {
public:
    explicit PacketBuffer(std::size_t capacity);

    PacketBuffer(const PacketBuffer&) = delete;
    PacketBuffer& operator=(const PacketBuffer&) = delete;
    PacketBuffer(PacketBuffer&&) = delete;
    PacketBuffer& operator=(PacketBuffer&&) = delete;
    ~PacketBuffer() = default;

    /// Inserts a packet. Returns false (and discards the packet) once the buffer is closed.
    bool push(RawPacket packet);

    /// Moves up to `maxCount` packets, oldest first, to the end of `out`.
    /// Returns the number of packets moved.
    std::size_t drain(std::vector<RawPacket>& out, std::size_t maxCount);

    /// Blocks until data is available, the buffer is closed or the timeout expires.
    /// Returns true when at least one packet can be drained.
    bool waitForData(std::chrono::milliseconds timeout);

    /// Marks the end of the stream: further pushes are rejected, waiters are woken up.
    void close();

    [[nodiscard]] bool closed() const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t capacity() const noexcept { return slots_.size(); }
    [[nodiscard]] std::uint64_t droppedCount() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable dataAvailable_;
    std::vector<RawPacket> slots_;  // fixed size, never reallocated after construction
    std::size_t head_ = 0;          // index of the oldest element
    std::size_t count_ = 0;
    std::uint64_t dropped_ = 0;
    bool closed_ = false;
};

}  // namespace tpi
