#include "Terminal.hpp"

#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#else
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace tpi {

namespace {
constexpr const char* kEnterScreen = "\x1b[?1049h\x1b[?25l\x1b[2J";
constexpr const char* kLeaveScreen = "\x1b[0m\x1b[?25h\x1b[?1049l";
}  // namespace

#if defined(_WIN32)

struct Terminal::State {
    HANDLE output = INVALID_HANDLE_VALUE;
    HANDLE input = INVALID_HANDLE_VALUE;
    DWORD originalOutputMode = 0;
    DWORD originalInputMode = 0;
    UINT originalCodePage = 0;
    bool outputModeSaved = false;
    bool inputModeSaved = false;
};

Terminal::Terminal() : state_(std::make_unique<State>()) {
    State& s = *state_;
    s.output = GetStdHandle(STD_OUTPUT_HANDLE);
    s.input = GetStdHandle(STD_INPUT_HANDLE);
    if (GetConsoleMode(s.output, &s.originalOutputMode) != 0) {
        s.outputModeSaved = true;
        SetConsoleMode(s.output,
                       s.originalOutputMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN);
    }
    if (GetConsoleMode(s.input, &s.originalInputMode) != 0) {
        s.inputModeSaved = true;
        // Keep ENABLE_PROCESSED_INPUT so Ctrl+C still raises SIGINT.
        const DWORD raw = (s.originalInputMode & ~static_cast<DWORD>(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
                                                                         ENABLE_QUICK_EDIT_MODE)) |
                          ENABLE_EXTENDED_FLAGS | ENABLE_PROCESSED_INPUT;
        SetConsoleMode(s.input, raw);
    }
    s.originalCodePage = GetConsoleOutputCP();
    SetConsoleOutputCP(CP_UTF8);
    write(kEnterScreen);
}

Terminal::~Terminal() {
    write(kLeaveScreen);
    const State& s = *state_;
    if (s.originalCodePage != 0) {
        SetConsoleOutputCP(s.originalCodePage);
    }
    if (s.inputModeSaved) {
        SetConsoleMode(s.input, s.originalInputMode);
    }
    if (s.outputModeSaved) {
        SetConsoleMode(s.output, s.originalOutputMode);
    }
}

TerminalSize Terminal::size() const {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(state_->output, &info) != 0) {
        return {info.srWindow.Right - info.srWindow.Left + 1, info.srWindow.Bottom - info.srWindow.Top + 1};
    }
    return {};
}

std::optional<KeyEvent> Terminal::readKey(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        const DWORD wait = remaining.count() > 0 ? static_cast<DWORD>(remaining.count()) : 0;
        if (WaitForSingleObject(state_->input, wait) != WAIT_OBJECT_0) {
            return std::nullopt;
        }
        INPUT_RECORD record{};
        DWORD read = 0;
        if (ReadConsoleInputW(state_->input, &record, 1, &read) == 0 || read == 0) {
            Sleep(wait);  // stdin is not a console (e.g. redirected): behave like a plain timeout
            return std::nullopt;
        }
        if (record.EventType != KEY_EVENT || record.Event.KeyEvent.bKeyDown == 0) {
            if (wait == 0) {
                return std::nullopt;
            }
            continue;  // mouse / focus / resize events
        }
        const KEY_EVENT_RECORD& key = record.Event.KeyEvent;
        switch (key.wVirtualKeyCode) {
            case VK_UP: return KeyEvent{KeyEvent::Code::Up};
            case VK_DOWN: return KeyEvent{KeyEvent::Code::Down};
            case VK_PRIOR: return KeyEvent{KeyEvent::Code::PageUp};
            case VK_NEXT: return KeyEvent{KeyEvent::Code::PageDown};
            case VK_HOME: return KeyEvent{KeyEvent::Code::Home};
            case VK_END: return KeyEvent{KeyEvent::Code::End};
            case VK_RETURN: return KeyEvent{KeyEvent::Code::Enter};
            case VK_ESCAPE: return KeyEvent{KeyEvent::Code::Escape};
            default: break;
        }
        const wchar_t ch = key.uChar.UnicodeChar;
        if (ch == 3) {
            return KeyEvent{KeyEvent::Code::Interrupt};
        }
        if (ch > 0 && ch < 128) {
            return KeyEvent{KeyEvent::Code::Character, static_cast<char>(ch)};
        }
    }
}

bool Terminal::isInteractive() { return _isatty(_fileno(stdout)) != 0 && _isatty(_fileno(stdin)) != 0; }

#else  // POSIX

struct Terminal::State {
    termios original{};
    bool restore = false;
};

Terminal::Terminal() : state_(std::make_unique<State>()) {
    if (tcgetattr(STDIN_FILENO, &state_->original) == 0) {
        termios raw = state_->original;
        raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));  // keep ISIG: Ctrl+C -> SIGINT
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
            state_->restore = true;
        }
    }
    write(kEnterScreen);
}

Terminal::~Terminal() {
    write(kLeaveScreen);
    if (state_->restore) {
        tcsetattr(STDIN_FILENO, TCSANOW, &state_->original);
    }
}

TerminalSize Terminal::size() const {
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        return {ws.ws_col, ws.ws_row};
    }
    return {};
}

std::optional<KeyEvent> Terminal::readKey(std::chrono::milliseconds timeout) {
    pollfd descriptor{STDIN_FILENO, POLLIN, 0};
    if (poll(&descriptor, 1, static_cast<int>(timeout.count())) <= 0) {
        return std::nullopt;
    }
    unsigned char buffer[16];
    const ssize_t length = ::read(STDIN_FILENO, buffer, sizeof buffer);
    if (length <= 0) {
        return std::nullopt;
    }
    if (buffer[0] == 0x1B) {
        if (length == 1) {
            return KeyEvent{KeyEvent::Code::Escape};
        }
        // CSI ("ESC [") and SS3 ("ESC O") cursor sequences
        if (length >= 3 && (buffer[1] == '[' || buffer[1] == 'O')) {
            switch (buffer[2]) {
                case 'A': return KeyEvent{KeyEvent::Code::Up};
                case 'B': return KeyEvent{KeyEvent::Code::Down};
                case 'H': return KeyEvent{KeyEvent::Code::Home};
                case 'F': return KeyEvent{KeyEvent::Code::End};
                case '1':
                case '7': return KeyEvent{KeyEvent::Code::Home};
                case '4':
                case '8': return KeyEvent{KeyEvent::Code::End};
                case '5': return KeyEvent{KeyEvent::Code::PageUp};
                case '6': return KeyEvent{KeyEvent::Code::PageDown};
                default: break;
            }
        }
        return std::nullopt;
    }
    if (buffer[0] == '\r' || buffer[0] == '\n') {
        return KeyEvent{KeyEvent::Code::Enter};
    }
    if (buffer[0] == 3) {
        return KeyEvent{KeyEvent::Code::Interrupt};
    }
    if (buffer[0] < 128) {
        return KeyEvent{KeyEvent::Code::Character, static_cast<char>(buffer[0])};
    }
    return std::nullopt;
}

bool Terminal::isInteractive() { return isatty(STDOUT_FILENO) != 0 && isatty(STDIN_FILENO) != 0; }

#endif

void Terminal::write(const std::string& data) const {
    std::fwrite(data.data(), 1, data.size(), stdout);
    std::fflush(stdout);
}

}  // namespace tpi
