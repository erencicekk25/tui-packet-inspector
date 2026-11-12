#include "TestFramework.hpp"

#include <cstdio>
#include <exception>

int main() {
    int failed = 0;
    for (const auto& test : tpitest::registry()) {
        try {
            test.body();
            std::printf("[ PASS ] %s\n", test.name);
        } catch (const std::exception& error) {
            ++failed;
            std::printf("[ FAIL ] %s\n         %s\n", test.name, error.what());
        }
    }
    std::printf("\n%zu tests, %d failed\n", tpitest::registry().size(), failed);
    return failed == 0 ? 0 : 1;
}
