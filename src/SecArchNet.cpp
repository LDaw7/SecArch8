#include "SecArchNet.h"
#include <iostream>
#include <vector>

SecArchNet::SecArchNet() : sock(INVALID_SOCKET), initialized(false) {
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) == 0) initialized = true;
    else std::cerr << "[!] WSAStartup failed.\n";
#else
    initialized = true;
#endif
}

SecArchNet::~SecArchNet() { cleanup(); }

void SecArchNet::cleanup() {
    if (sock != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        sock = INVALID_SOCKET;
    }
#ifdef _WIN32
    if (initialized) WSACleanup();
#endif
}

bool SecArchNet::start_listener() {
    if (!initialized) return false;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return false;

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT_SERVER);

    // Modern Cast: reinterpret_cast for type safety visibility
    if (bind(sock, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "[!] Bind Failed. Port in use?\n";
        return false;
    }

    // Set Timeout (1 Second)
#ifdef _WIN32
    DWORD timeout = 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

    std::cout << "[*] SecArch-8 Listening on UDP " << PORT_SERVER << "\n";
    return true;
}

std::vector<uint8_t> SecArchNet::listen_for_packet() {
    struct sockaddr_in client;
    int len = sizeof(client);

#ifdef VULNERABLE
    // ==========================================
    // [!] VULNERABLE MODE (Stack Buffer Overflow)
    // ==========================================
    
    constexpr int SAFE_SIZE = 64;
    constexpr int OVERFLOW_SIZE = 1024;
    
    // In C++, struct members are guaranteed to be allocated in order of declaration.
    // This ensures 'canary' is always physically located AFTER 'buffer' in memory,
    // making the overflow behavior consistent across different compilers/flags.
    struct StackFrame {
        char buffer[SAFE_SIZE]; 
        volatile uint32_t canary; 
    };

    StackFrame frame;
    
    // Initialise Canary
    // We use volatile to prevent the compiler from optimising out the check 
    // if it determines we never "legally" write to this variable.
    frame.canary = 0xCAFEBABE; 

    std::cout << "[!] WARN: Vulnerable Mode Active. Buffer: " << SAFE_SIZE << " bytes.\n";

    #ifdef CANARY
        std::cout << "[*] DEFENSE: Stack Canary Enabled (0xCAFEBABE)\n";
    #endif

    // The Vulnerability: We read OVERFLOW_SIZE (1024) into frame.buffer (64)
#ifdef _WIN32
    int bytes = recvfrom(sock, frame.buffer, OVERFLOW_SIZE, 0, reinterpret_cast<struct sockaddr*>(&client), &len);
#else
    ssize_t bytes = recvfrom(sock, frame.buffer, OVERFLOW_SIZE, 0, reinterpret_cast<struct sockaddr*>(&client), (socklen_t*)&len);
#endif

    // 3. Canary Check (The Mitigation)
    #ifdef CANARY
    if (frame.canary != 0xCAFEBABE) {
        std::cerr << "\n[!!!] STACK SMASHING DETECTED [!!!]\n";
        std::cerr << "[*] Canary Value Corrupted: 0x" << std::hex << frame.canary << "\n";
        std::cerr << "[*] Terminating process to prevent code execution.\n";
        exit(139); // SIGSEGV exit code
    }
    #endif

    if (bytes > 0) {
        std::cout << "[+] Packet Received: " << bytes << " bytes.\n";
        // Convert to vector for the CPU
        // Safe copy of raw memory (even if that memory was overflowed)
        const uint8_t* raw_ptr = reinterpret_cast<const uint8_t*>(&frame);
        return std::vector<uint8_t>(raw_ptr, raw_ptr + bytes);
    }
    return {};

#else
    // ==========================================
    // [!] SECURE MODE (Default)
    // ==========================================
    
    std::vector<uint8_t> packet(1024);
    
#ifdef _WIN32
    int bytes = recvfrom(sock, reinterpret_cast<char*>(packet.data()), static_cast<int>(packet.size()), 0, reinterpret_cast<struct sockaddr*>(&client), &len);
#else
    ssize_t bytes = recvfrom(sock, reinterpret_cast<char*>(packet.data()), packet.size(), 0, reinterpret_cast<struct sockaddr*>(&client), (socklen_t*)&len);
#endif

    if (bytes > 0) {

        packet.resize(bytes);
        
        std::cout << "[+] Packet Received: " << bytes << " bytes.\n";
        return packet;
    }
    return {};
#endif
}