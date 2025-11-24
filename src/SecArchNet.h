#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <cstdint> // Added for uint8_t/uint32_t type safety

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
using SOCKET = int;
constexpr int INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
#endif

constexpr int PORT_SERVER = 0x1984;

class SecArchNet {
public:
    SecArchNet();
    ~SecArchNet();

    SecArchNet(const SecArchNet&) = delete;
    SecArchNet& operator=(const SecArchNet&) = delete;

    bool start_listener();
    std::vector<uint8_t> listen_for_packet();

private:
    SOCKET sock;
    struct sockaddr_in server_addr;
    bool initialized;
    void cleanup();
};