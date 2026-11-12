#include "PacketBuffer.hpp"

#include <algorithm>
#include <utility>

namespace tpi {

PacketBuffer::PacketBuffer(std::size_t capacity) : slots_(std::max<std::size_t>(capacity, 1)) {}

bool PacketBuffer::push(RawPacket packet) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) {
            return false;
        }
        const std::size_t tail = (head_ + count_) % slots_.size();
        slots_[tail] = std::move(packet);
        if (count_ == slots_.size()) {
            // Ring is full: the slot we just wrote was the oldest one.
            head_ = (head_ + 1) % slots_.size();
            ++dropped_;
        } else {
            ++count_;
        }
    }
    dataAvailable_.notify_one();
    return true;
}

std::size_t PacketBuffer::drain(std::vector<RawPacket>& out, std::size_t maxCount) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t n = std::min(count_, maxCount);
    out.reserve(out.size() + n);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(std::move(slots_[head_]));
        slots_[head_] = RawPacket{};
        head_ = (head_ + 1) % slots_.size();
    }
    count_ -= n;
    return n;
}

bool PacketBuffer::waitForData(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    dataAvailable_.wait_for(lock, timeout, [this] { return count_ > 0 || closed_; });
    return count_ > 0;
}

void PacketBuffer::close() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
    }
    dataAvailable_.notify_all();
}

bool PacketBuffer::closed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
}

std::size_t PacketBuffer::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return count_;
}

std::uint64_t PacketBuffer::droppedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

}  // namespace tpi
