# SecArch-8 Network Interface Documentation

## Table of Contents
1.  [Overview](#overview)
2.  [Architectural Design](#architectural-design)
3.  [Detailed Component Logic](#detailed-component-logic)
    * [Lifecycle Management](#lifecycle-management)
    * [The Listener Logic](#the-listener-logic)
    * [Security Modes (The Core Feature)](#security-modes-the-core-feature)
4.  [Build Configurations & Usage](#build-configurations--usage)
5.  [Integration Guide](#integration-guide)
6.  [Common Pitfalls & Best Practices](#common-pitfalls--best-practices)
7.  [Frequently Asked Questions](#frequently-asked-questions)

---

## 1. Overview

The `SecArchNet` module serves as the network interface controller (NIC) for the SecArch-8 Emulator. Its primary purpose is to receive raw binary payloads via UDP and pass them to the CPU for execution.

However, from an educational and research perspective, this module is unique. It is designed as a **polymorphic security lab**. Through the use of preprocessor directives, this single file can be compiled into three distinct states:
1.  **Production Secure:** Modern C++ memory safety standards.
2.  **Vulnerable:** Simulating legacy C-style stack buffer overflows.
3.  **Mitigated:** Simulating stack canaries (stack cookies) for intrusion detection.

This allows the user to study both the exploitation of memory corruption vulnerabilities and the implementation of defensive programming techniques within a controlled environment.

---

## 2. Architectural Design

The class follows the **RAII (Resource Acquisition Is Initialization)** pattern. This is a critical C++ idiom where resource management (in this case, network sockets) is tied to the lifespan of the object.

* **Construction:** Initialises the underlying OS socket libraries (Winsock on Windows, standard headers on *nix).
* **Destruction:** Automatically closes handles and performs cleanup, preventing resource leaks even if exceptions occur.

The class isolates platform-specific networking code (Windows vs Linux) using `#ifdef` macros, providing a unified API (`start_listener`, `listen_for_packet`) to the consumer.

---

## 3. Detailed Component Logic

### Lifecycle Management
**`SecArchNet::SecArchNet()` / `~SecArchNet()`**

The constructor handles the boilerplate required to bring up the network stack.
* **Windows Specifics:** Calls `WSAStartup`. This is often missed by junior developers moving from Linux to Windows. Without this, no socket operations will function.
* **Cleanup:** The destructor checks if the socket is valid (`INVALID_SOCKET`) before closing it, ensuring we do not attempt to close a null handle.

### The Listener Logic
**`bool start_listener()`**

This function sets up the UDP socket on port `0x1984`.
1.  **Socket Creation:** uses `AF_INET` (IPv4) and `SOCK_DGRAM` (UDP). UDP is chosen over TCP to preserve packet boundaries, which is preferable for shellcode transmission.
2.  **Binding:** Binds to `INADDR_ANY`, meaning it listens on all available network interfaces (localhost, Wi-Fi, Ethernet).
3.  **Timeout Configuration:** Sets a 1-second timeout on receive operations using `setsockopt`.
    * *Design Note:* Without a timeout, the `recvfrom` call is blocking. If the emulator is running a GUI or a main loop, a blocking network call will freeze the entire application until a packet arrives.

### Security Modes (The Core Feature)
**`std::vector<uint8_t> listen_for_packet()`**

This function contains the logic branching.

#### A. Secure Mode (Default)
When no flags are set, the code uses `std::array<char, 1024>`.
* **Logic:** The buffer size (`1024`) matches the maximum bytes requested in `recvfrom`.
* **Result:** It is mathematically impossible to overflow this buffer using standard input methods. This represents correct modern C++ implementation.

#### B. Vulnerable Mode (`-DVULNERABLE`)
When the `VULNERABLE` flag is defined, the code reverts to an unsafe C-style implementation.
* **The Flaw:** A stack buffer `char buffer[64]` is declared.
* **The Exploit:** The `recvfrom` call is instructed to accept up to `1024` bytes (`OVERFLOW_SIZE`).
* **Consequence:** If a packet larger than 64 bytes is received, the extra data overwrites the stack memory immediately following the buffer. In the x86/x64 calling convention, this area typically contains the **Saved Frame Pointer (EBP)** and the **Return Address (EIP/RIP)**. Overwriting the Return Address grants control over the instruction pointer.

#### C. Canary Mode (`-DVULNERABLE -DCANARY`)
This mode adds a software-based mitigation.
* **The Guard:** A `volatile uint32_t canary` variable is placed on the stack immediately *after* the buffer but *before* the return address. It is initialised to `0xCAFEBABE`.
* **The Check:** After `recvfrom` writes data, but *before* the function returns, the code checks if `canary == 0xCAFEBABE`.
* **Detection:** Because the stack fills linearly, an attacker attempting to reach the Return Address *must* overwrite the Canary first. If the value has changed, the program detects the attack and terminates (`exit(139)`) before the corrupted return address is used.

---

## 4. Build Configurations & Usage

To switch between modes, you must recompile the project using specific CMake flags.

### 1. Secure Build (Default)
Safe for general use.
```bash
cmake ..
cmake --build .
```

### 2. Vulnerable Build
Enables the buffer overflow laboratory.
```bash
# Windows (PowerShell)
cmake -DCMAKE_CXX_FLAGS="/DVULNERABLE" ..
cmake --build .

# Linux / Mac
cmake -DCMAKE_CXX_FLAGS="-DVULNERABLE" ..
make
```

### 3. Mitigated Build (Canary)
Enables the vulnerability but adds the stack cookie check.
```bash
# Windows
cmake -DCMAKE_CXX_FLAGS="/DVULNERABLE /DCANARY" ..
cmake --build .

# Linux / Mac
cmake -DCMAKE_CXX_FLAGS="-DVULNERABLE -DCANARY" ..
make
```

---

## 5. Integration Guide

To use this class in your main application loop:

```cpp
#include "SecArchNet.h"

int main() {
    SecArchNet net;

    // 1. Attempt to start the listener
    if (!net.start_listener()) {
        std::cerr << "Failed to open port 0x1984.\n";
        return 1;
    }

    // 2. Main Loop
    while (true) {
        // This will block for 1 second, then return empty if no packet
        std::vector<uint8_t> payload = net.listen_for_packet();

        if (!payload.empty()) {
            // Pass payload to CPU emulator...
            cpu.inject_memory(payload);
            cpu.run();
        }
    }
    return 0;
}
```

---

## 6. Common Pitfalls & Best Practices

### Pitfalls
1.  **Compiler Optimization:** In Vulnerable Mode, variables are marked `volatile`. Without this, modern compilers (O2/O3 optimization levels) are smart enough to realise the canary check might be redundant or might reorder the stack variables, rendering the specific overflow layout unpredictable.
2.  **Firewall Rules:** UDP Port 6532 (`0x1984`) is non-standard. Ensure your local firewall allows inbound UDP traffic on this port, or the listener will fail silently or receive nothing.
3.  **Buffer Alignment:** On some architectures, stack variables are aligned to 8 or 16-byte boundaries. This means a 64-byte buffer might actually take up 72 bytes of space. When calculating exploit offsets, always inspect the memory in a debugger (GDB) rather than assuming exact byte counts.

### Best Practices
* **Never use `recv` into a C-array without `sizeof`:** The root cause of the vulnerability in this code is decoupling the buffer size (`64`) from the receive limit (`1024`). Always use `sizeof(buffer)` or `std::array::size()` in the length argument.
* **Fail Safe:** The Canary implementation calls `exit(139)`. In a real high-availability system, you might log the intrusion and restart the service rather than crashing silently.
* **Separation of Concerns:** This network class does not know about the CPU. It only returns raw bytes. This decoupling makes the code testable and maintainable.

---

## 7. Questions asked by HTB players

**Q: Why does the program crash when I send a long packet in Vulnerable Mode?**
**A:** This is the intended behaviour. You have successfully overwritten the Return Address with garbage data. When the function tried to return, the CPU jumped to an invalid memory address (Segmentation Fault). To exploit this, you must overwrite the return address with a pointer to valid code (like a NOP sled).

**Q: Can I bypass the Canary?**
**A:** Yes, theoretically. If you can read memory (information leak) to discover the Canary value, or if you can brute-force the value (harder on 32-bit, impossible on 64-bit within reasonable time), you can include the correct Canary value in your payload at the correct offset, "repairing" the stack as you overflow it.

**Q: Why use UDP instead of TCP?**
**A:** UDP is connectionless. This allows for "fire and forget" payload injection, which is typical in fuzzing and exploit development scenarios. It reduces the overhead of the TCP 3-way handshake.

**Q: What is `0xCAFEBABE`?**
**A:** It is a "Magic Number" (hexspeak) used widely in computing, notably in Java class files and Mach-O binaries. It is used here simply as a recognisable pattern to identify the Canary in a debugger.