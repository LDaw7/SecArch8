#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include <iostream>
#include "Utils.h"

using Byte = uint8_t;
using Word = uint16_t;

constexpr int MEMORY_SIZE = 65536;

enum class Reg : uint8_t { 
    B=0, C=1, L=2, H=3, A=4, M=5 
};

constexpr Byte FLAG_Z = 0x80; 
constexpr Byte FLAG_N = 0x08; 

class SecArchCPU {
public:
    SecArchCPU();
    ~SecArchCPU();

    // Prevent copying (Rule of Five)
    SecArchCPU(const SecArchCPU&) = delete;
    SecArchCPU& operator=(const SecArchCPU&) = delete;
    SecArchCPU(SecArchCPU&&) = delete;
    SecArchCPU& operator=(SecArchCPU&&) = delete;

    void reset();
    void inject_memory(const std::vector<Byte>& payload, Word start_addr = 0);
    void run(int max_cycles = 10000);

private:
    std::vector<Byte> memory;
    std::array<Byte, 6> registers; 
    std::array<Byte, 2> index_regs; 
    Word pc;
    Word sp;
    Byte flags;
    bool halted;

    Byte read_byte(Word address);
    void write_byte(Word address, Byte data);
    Word get_hl();
    void set_flags_zn(Byte val);

    using InstHandler = void (SecArchCPU::*)(Byte opcode);
    std::array<InstHandler, 256> inst_table;
    void init_table();

    // Instructions
    void inst_nop(Byte op);       
    void inst_ld_imm(Byte op);      
    void inst_sto_abs(Byte op);     
    void inst_syscall(Byte op);     
    void inst_unimplemented(Byte op);
    void inst_group_move(Byte op);  
    void inst_group_alu(Byte op);   
};