#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace tpi {

struct TerminalSize {
    int columns = 80;
    int rows = 24;
    bool operator==(const TerminalSize& other) const noexcept { return columns == other.columns && rows == other.rows; }
    bool operator!=(const TerminalSize& other) const noexcept { return !(*this == other); }
};

struct KeyEvent {
    enum class Code { Character, Up, Down, PageUp, PageDown, Home, End, Enter, Escape, Interrupt };
    Code code = Code::Character;
    char character = 0;  ///< Valid when code == Character (ASCII only)
};

/// RAII terminal session.
///
/// Construction switches the terminal into a raw, non-echoing, alternate-screen mode with a
/// hidden cursor (and enables VT processing + UTF-8 on Windows). Destruction restores every
/// setting it changed, even when the dashboard exits through an exception.
class Terminal {
public:
    Terminal();
    ~Terminal();

    Terminal(const Terminal&) = delete;
    Terminal& operator=(const Terminal&) = delete;
    Terminal(Terminal&&) = delete;
    Terminal& operator=(Terminal&&) = delete;

    [[nodiscard]] TerminalSize size() const;
    void write(const std::string& data) const;

    /// Waits up to `timeout` for a key press.
    std::optional<KeyEvent> readKey(std::chrono::milliseconds timeout);

    /// True when both stdin and stdout are attached to a terminal.
    [[nodiscard]] static bool isInteractive();

private:
    struct State;  // platform specific (termios / console modes)
    std::unique_ptr<State> state_;
};

}  // namespace tpi
