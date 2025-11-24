#include "SecArchCPU.h"
#include "SecArchNet.h"
#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "======================================\n";
    std::cout << "     SecArch-8 Research Platform      \n";
    std::cout << "======================================\n";

    if(argc < 2) {
        std::cout << "Usage: ./SecArch8 -S (Local Shellcode) | -N (Net Listen)\n";
        return 0;
    }

    std::string mode = argv[1];
    SecArchCPU cpu;

    if(mode == "-S") {
        std::cout << "[*] Mode: Local Shellcode Verification\n";
        // Test: Load 2, Trap.
        std::vector<Byte> shellcode = { 0x43, 0x02, 0xFF }; 
        cpu.inject_memory(shellcode);
        cpu.run();
    }
    else if(mode == "-N") {
        std::cout << "[*] Mode: Network Vulnerability Listener\n";
        SecArchNet net;
        if (!net.start_listener()) return 1;

        bool running = true;
        while(running) {
            auto packet = net.listen_for_packet();
            
            if (!packet.empty()) {
                std::cout << "[*] Injecting payload into memory...\n";
                cpu.reset(); 
                cpu.inject_memory(packet);
                cpu.run();
                std::cout << "[*] Execution complete. Waiting for reset...\n";
            }
        }
    }

    return 0;
}