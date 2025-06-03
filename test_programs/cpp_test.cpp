// C++ test program with advanced features for static analysis
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <memory>
#include <map>
#include <algorithm>
#include <random>
#include <sstream>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <dlfcn.h>
#endif

// Suspicious constants
const char* C2_SERVER = "msftupdater.com";
const int C2_PORT = 443;
constexpr unsigned char XOR_KEY[] = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};

// Template metaprogramming for obfuscation
template<size_t... Indices>
struct indices {};

template<size_t N, size_t... Is>
struct build_indices : build_indices<N-1, N-1, Is...> {};

template<size_t... Is>
struct build_indices<0, Is...> : indices<Is...> {};

template<size_t N>
using make_indices = build_indices<N>;

// Simple string obfuscation
class ObfuscatedString {
    static constexpr char encrypted[] = {0x1c, 0x32, 0x3a, 0x3a, 0x35, 0x0a, 0x47, 0x73, 0x64, 0x62, 0x60, 0x68};
public:
    static std::string decrypt() {
        std::string result;
        for(size_t i = 0; i < sizeof(encrypted); i++) {
            result += char(encrypted[i] ^ XOR_KEY[i % sizeof(XOR_KEY)]);
        }
        return result;
    }
};

// Anti-debugging class
class AntiDebug {
public:
    static bool isDebuggerPresent() {
#ifdef _WIN32
        return IsDebuggerPresent();
#else
        return ptrace(PTRACE_TRACEME, 0, 1, 0) == -1;
#endif
    }

    static bool checkBreakpoints() {
        volatile int x = 0;
        __asm__ volatile("int3");
        x = 1;
        return x == 1;
    }

    static bool timingCheck() {
        auto start = std::chrono::high_resolution_clock::now();
        volatile int sum = 0;
        for(int i = 0; i < 1000000; i++) {
            sum += i;
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        return duration.count() > 100; // Suspiciously slow
    }
};

// Polymorphic malware simulation
class Payload {
public:
    virtual ~Payload() = default;
    virtual void execute() = 0;
};

class NetworkPayload : public Payload {
    std::string server;
    int port;
public:
    NetworkPayload(const std::string& s, int p) : server(s), port(p) {}

    void execute() override {
        std::cout << "Connecting to " << server << ":" << port << std::endl;
        // Simulate beacon
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
};

class FilePayload : public Payload {
    std::string target;
public:
    FilePayload(const std::string& t) : target(t) {}

    void execute() override {
        std::cout << "Encrypting file: " << target << std::endl;
        // Simulate file encryption
        std::vector<unsigned char> key(32);
        std::generate(key.begin(), key.end(), std::rand);
    }
};

// Resource exhaustion
class ResourceHog {
    std::vector<std::unique_ptr<std::vector<char>>> memory_bombs;

public:
    void consumeMemory() {
        try {
            for(int i = 0; i < 100; i++) {
                auto bomb = std::make_unique<std::vector<char>>(10 * 1024 * 1024); // 10MB each
                std::fill(bomb->begin(), bomb->end(), 0xFF);
                memory_bombs.push_back(std::move(bomb));
            }
        } catch(const std::bad_alloc&) {
            std::cout << "Memory exhausted" << std::endl;
        }
    }

    void consumeCPU() {
        std::vector<std::thread> threads;
        for(unsigned i = 0; i < std::thread::hardware_concurrency(); i++) {
            threads.emplace_back([]() {
                volatile double result = 0;
                for(long j = 0; j < 100000000; j++) {
                    result += std::sin(j) * std::cos(j);
                }
            });
        }
        for(auto& t : threads) {
            t.join();
        }
    }
};

// Exploit simulation (buffer overflow pattern)
void vulnerableFunction(const char* input) {
    char buffer[64];
    strcpy(buffer, input); // Vulnerable to buffer overflow
    std::cout << "Buffer content: " << buffer << std::endl;
}

// Self-modifying code simulation
class SelfModifier {
    static void modifyCode() {
        unsigned char* code = reinterpret_cast<unsigned char*>(&modifyCode);
        // Would normally change memory protections and modify code
        volatile unsigned char temp = code[0];
        (void)temp; // Avoid unused warning
    }

public:
    static void execute() {
        modifyCode();
    }
};

// Process injection simulation
class ProcessInjector {
public:
    static void injectCode() {
#ifdef _WIN32
        // Windows process injection pattern
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if(snapshot != INVALID_HANDLE_VALUE) {
            CloseHandle(snapshot);
        }
#else
        // Linux shared library injection pattern
        void* handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle) {
            dlclose(handle);
        }
#endif
    }
};

// Persistence mechanism
class Persistence {
public:
    static void install() {
#ifdef _WIN32
        // Registry persistence
        std::cout << "Would modify HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" << std::endl;
#else
        // Cron persistence
        std::string cronJob = "* * * * * " + std::string(getenv("_") ?: "/tmp/malware");
        std::cout << "Would add cron job: " << cronJob << std::endl;
#endif
    }
};

// Main function with high cyclomatic complexity
int main(int argc, char* argv[]) {
    std::cout << "C++ Test Binary for Analysis" << std::endl;

    // Anti-analysis checks
    if(AntiDebug::isDebuggerPresent()) {
        std::cout << "Debugger detected!" << std::endl;
        return 1;
    }

    if(AntiDebug::timingCheck()) {
        std::cout << "Timing anomaly detected!" << std::endl;
        return 2;
    }

    // Command line argument processing (complex branching)
    if(argc > 1) {
        std::string arg(argv[1]);
        if(arg == "--network") {
            auto payload = std::make_unique<NetworkPayload>(C2_SERVER, C2_PORT);
            payload->execute();
        } else if(arg == "--file") {
            if(argc > 2) {
                auto payload = std::make_unique<FilePayload>(argv[2]);
                payload->execute();
            }
        } else if(arg == "--inject") {
            ProcessInjector::injectCode();
        } else if(arg == "--persist") {
            Persistence::install();
        } else if(arg == "--overflow") {
            if(argc > 2) {
                vulnerableFunction(argv[2]);
            }
        } else if(arg == "--resource") {
            ResourceHog hog;
            hog.consumeMemory();
            hog.consumeCPU();
        }
    }

    // Obfuscated string decryption
    std::string hidden = ObfuscatedString::decrypt();
    std::cout << "Decrypted: " << hidden << std::endl;

    // Self-modification attempt
    SelfModifier::execute();

    // Environment fingerprinting
    std::map<std::string, std::string> env_vars = {
        {"USER", ""},
        {"HOME", ""},
        {"PATH", ""},
        {"TEMP", ""}
    };

    for(auto& [key, value] : env_vars) {
        const char* val = std::getenv(key.c_str());
        if(val) {
            value = val;
            // Check for sandbox indicators
            if(value.find("sandbox") != std::string::npos ||
               value.find("virus") != std::string::npos ||
               value.find("malware") != std::string::npos) {
                std::cout << "Sandbox environment detected!" << std::endl;
                return 3;
            }
        }
    }

    // Create some threads for complexity
    std::vector<std::thread> workers;
    for(int i = 0; i < 3; i++) {
        workers.emplace_back([i]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * i));
            std::cout << "Worker " << i << " completed" << std::endl;
        });
    }

    for(auto& w : workers) {
        w.join();
    }

    std::cout << "Program completed successfully" << std::endl;
    return 0;
}
