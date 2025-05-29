#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Simple test program to demonstrate unpacked vs packed binary analysis
int main(int argc, char* argv[]) {
    printf("UPX Test Program v1.0\n");
    printf("This is a simple test binary for entropy analysis.\n");
    
    // Add some identifiable strings
    const char* secret = "SECRET_KEY_12345";
    const char* config = "CONFIG_PATH=/etc/test/config.ini";
    
    // Some basic operations
    if (argc > 1) {
        printf("Hello, %s!\n", argv[1]);
        
        // String operations
        char buffer[256];
        strncpy(buffer, argv[1], sizeof(buffer)-1);
        buffer[sizeof(buffer)-1] = '\0';
        
        printf("Length: %zu\n", strlen(buffer));
    }
    
    // Add some data patterns
    unsigned char data[] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
        0x72, 0x6c, 0x64, 0x21, 0x0a, 0x00, 0x00, 0x00
    };
    
    printf("Data: ");
    for (int i = 0; i < sizeof(data); i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
    
    return 0;
}