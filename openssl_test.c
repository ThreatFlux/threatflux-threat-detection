#include <stdio.h>
#include <string.h>

// Simulate OpenSSL usage
void crypto_function() {
    // Simulated crypto operation
    char version[] = "OpenSSL 1.0.1f 6 Jan 2014"; // Vulnerable version (Heartbleed)
    printf("Using %s\n", version);
    
    // Simulate library loading
    char libssl[] = "libssl.so.1.0.0";
    char libcrypto[] = "libcrypto.so.1.0.0";
    
    printf("Loading %s\n", libssl);
    printf("Loading %s\n", libcrypto);
}

int main() {
    crypto_function();
    
    // Other library references
    char zlib_version[] = "zlib version 1.2.11";
    printf("%s\n", zlib_version);
    
    return 0;
}