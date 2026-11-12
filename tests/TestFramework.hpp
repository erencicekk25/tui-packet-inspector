#pragma once

// Minimal, dependency-free unit test harness (keeps the project free of external deps).

#include <exception>
#include <string>
#include <vector>

namespace tpitest {

struct TestCase {
    const char* name;
    void (*body)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const char* name, void (*body)()) { registry().push_back({name, body}); }
};

class Failure : public std::exception {
public:
    Failure(const char* file, int line, const std::string& expression)
        : message_(std::string(file) + ":" + std::to_string(line) + ": CHECK(" + expression + ") failed") {}
    [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }

private:
    std::string message_;
};

}  // namespace tpitest

#define TPI_TEST(name)                                                    \
    static void name();                                                   \
    static const ::tpitest::Registrar name##_registrar(#name, &name);     \
    static void name()

#define CHECK(expression)                                                 \
    do {                                                                  \
        if (!(expression)) {                                              \
            throw ::tpitest::Failure(__FILE__, __LINE__, #expression);    \
        }                                                                 \
    } while (false)

#define CHECK_EQ(actual, expected) CHECK((actual) == (expected))
