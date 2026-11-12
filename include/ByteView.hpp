#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tpi {

/// Non-owning, bounds-aware view over a byte range (a tiny C++17 stand-in for std::span).
///
/// Every decoder in this project reads packet data exclusively through ByteView and guards
/// each access with has(), so malformed or truncated packets can never read out of bounds.
class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}
    explicit ByteView(const std::vector<std::uint8_t>& bytes) noexcept : data_(bytes.data()), size_(bytes.size()) {}

    [[nodiscard]] constexpr const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }

    /// True when `count` bytes starting at `offset` are inside the view.
    [[nodiscard]] constexpr bool has(std::size_t offset, std::size_t count) const noexcept {
        return offset <= size_ && count <= size_ - offset;
    }

    // Unchecked accessors: callers must validate with has() first.
    [[nodiscard]] constexpr std::uint8_t u8(std::size_t offset) const noexcept { return data_[offset]; }
    [[nodiscard]] constexpr std::uint16_t be16(std::size_t offset) const noexcept {
        return static_cast<std::uint16_t>((data_[offset] << 8) | data_[offset + 1]);
    }
    [[nodiscard]] constexpr std::uint16_t le16(std::size_t offset) const noexcept {
        return static_cast<std::uint16_t>(data_[offset] | (data_[offset + 1] << 8));
    }
    [[nodiscard]] constexpr std::uint32_t be32(std::size_t offset) const noexcept {
        return (static_cast<std::uint32_t>(be16(offset)) << 16) | be16(offset + 2);
    }

    /// Sub-range starting at `offset`; clamped to the view, never out of bounds.
    [[nodiscard]] constexpr ByteView subview(std::size_t offset, std::size_t count = static_cast<std::size_t>(-1)) const noexcept {
        if (offset >= size_) {
            return ByteView{};
        }
        const std::size_t available = size_ - offset;
        return ByteView{data_ + offset, count < available ? count : available};
    }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

}  // namespace tpi
