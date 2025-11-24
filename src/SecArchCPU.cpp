#include "SecArchCPU.h"
#include <iomanip>
#include <cstring>

SecArchCPU::SecArchCPU() : memory(MEMORY_SIZE, 0) {
    init_table();
    reset();
}

SecArchCPU::~SecArchCPU() {}

void SecArchCPU::reset() {
    std::fill(registers.begin(), registers.end(), 0);
    std::fill(index_regs.begin(), index_regs.end(), 0);
    std::fill(memory.begin(), memory.end(), 0);
    pc = 0;
    sp = 0;
    flags = 0;
    halted = false;
}

void SecArchCPU::inject_memory(const std::vector<Byte>& payload, Word start_addr) {
    size_t limit = (payload.size() > (MEMORY_SIZE - start_addr)) ? (MEMORY_SIZE - start_addr) : payload.size();
    for(size_t i = 0; i < limit; i++) {
        memory[start_addr + i] = payload[i];
    }
}

Byte SecArchCPU::read_byte(Word address) {
    if (address >= MEMORY_SIZE) {
        std::cerr << "[!] SEGFAULT: Read at 0x" << std::hex << address << "\n";
        halted = true;
        return 0;
    }
    return memory[address];
}

void SecArchCPU::write_byte(Word address, Byte data) {
    if (address >= MEMORY_SIZE) {
        std::cerr << "[!] SEGFAULT: Write at 0x" << std::hex << address << "\n";
        halted = true;
        return;
    }
    memory[address] = data;
}

Word SecArchCPU::get_hl() {
    return (static_cast<Word>(registers[to_idx(Reg::H)]) << 8) | registers[to_idx(Reg::L)];
}

void SecArchCPU::set_flags_zn(Byte val) {
    flags = (val == 0) ? (flags | FLAG_Z) : (flags & ~FLAG_Z);
    flags = (val & 0x80) ? (flags | FLAG_N) : (flags & ~FLAG_N);
}

void SecArchCPU::run(int max_cycles) {
    int cycles = 0;
    while(!halted && cycles < max_cycles) {
        Byte op = read_byte(pc++);
        (this->*inst_table[op])(op);
        cycles++;
    }
}

void SecArchCPU::init_table() {
    inst_table.fill(&SecArchCPU::inst_unimplemented);

    inst_table[0x00] = &SecArchCPU::inst_nop;
    inst_table[0xFF] = &SecArchCPU::inst_syscall;
    inst_table[0x43] = &SecArchCPU::inst_ld_imm; 
    inst_table[0x04] = &SecArchCPU::inst_sto_abs;

    for (int op = 0; op < 256; op++) {
        Byte source = op >> 4;
        Byte dest = op & 0x0F;
        if ((source >= 0x0A && source <= 0x0F) && (dest >= 0x00 && dest <= 0x05)) {
            inst_table[op] = &SecArchCPU::inst_group_move;
        }
        if (op == 0x95) inst_table[op] = &SecArchCPU::inst_group_alu; 
    }
}

void SecArchCPU::inst_group_move(Byte opcode) {
    Byte src_idx = (opcode >> 4) & 0x0F;
    Byte dst_idx = opcode & 0x0F;

    auto map_reg = [](Byte val) -> int {
        if (val <= 0x05) return val; 
        if (val >= 0x0A && val <= 0x0F) return val - 0x0A; 
        return -1;
    };

    int s_reg = map_reg(src_idx);
    int d_reg = map_reg(dst_idx);

    if (s_reg == -1 || d_reg == -1) return;

    Byte val = 0;
    if (s_reg == to_idx(Reg::M)) val = read_byte(get_hl());
    else val = registers[s_reg];

    if (d_reg == to_idx(Reg::M)) write_byte(get_hl(), val);
    else registers[d_reg] = val;
}

void SecArchCPU::inst_group_alu(Byte opcode) {
    if (opcode == 0x95) { 
        registers[to_idx(Reg::A)]++;
        set_flags_zn(registers[to_idx(Reg::A)]);
    }
}

void SecArchCPU::inst_nop(Byte) { 
    // NOP Sled handler: Do nothing, just consume cycle
}
void SecArchCPU::inst_unimplemented(Byte) { }

void SecArchCPU::inst_ld_imm(Byte) {
    Byte val = read_byte(pc++);
    registers[to_idx(Reg::A)] = val;
    set_flags_zn(val);
}

void SecArchCPU::inst_sto_abs(Byte) {
    Byte lb = read_byte(pc++);
    Byte hb = read_byte(pc++);
    Word addr = (static_cast<Word>(hb) << 8) | lb;
    write_byte(addr, registers[to_idx(Reg::A)]);
}

void SecArchCPU::inst_syscall(Byte) {
    Byte id = registers[to_idx(Reg::A)];
    std::cout << "\n[!] SYS-TRAP: Call ID 0x" << std::hex << (int)id << " halted.\n";
    halted = true; 
}