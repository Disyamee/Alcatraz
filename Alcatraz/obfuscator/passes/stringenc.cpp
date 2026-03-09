#include "../obfuscator.h"

#include <random>

using namespace asmjit;

bool obfuscator::encrypt_strings(std::vector<obfuscator::function_t>::iterator& func, std::vector<obfuscator::instruction_t>::iterator& instruction, PIMAGE_SECTION_HEADER new_section) {

	// Only handle LEA with RIP-relative 32-bit displacement
	if (!instruction->has_relative || instruction->isjmpcall)
		return false;
	if (instruction->relative.size != 32)
		return false;

	// Bail early if we can't look up the destination register (avoids partial state changes)
	auto x86_register_map = lookupmap.find(instruction->zyinstr.operands[0].reg.value);
	if (x86_register_map == lookupmap.end())
		return false;

	auto base = pe->get_buffer()->data();

	auto rdata = pe->get_section(".rdata");
	if (!rdata)
		return false;

	uint64_t rdata_start = (uint64_t)base + rdata->VirtualAddress;
	uint64_t rdata_end = rdata_start + rdata->Misc.VirtualSize;
	uint64_t data_addr = instruction->location_of_data;

	if (data_addr < rdata_start || data_addr >= rdata_end)
		return false;

	// Only encrypt addresses that look like the START of a string
	// (previous byte is null terminator of prior string, or we're at the very beginning of .rdata).
	if (data_addr > rdata_start) {
		if (*(const uint8_t*)(data_addr - 1) != 0)
			return false;
	}

	// Validate: printable ASCII string, null-terminated, reasonable length
	const char* str = reinterpret_cast<const char*>(data_addr);
	uint32_t len = 0;
	while (len < 4097 && str[len] != '\0') {
		uint8_t c = (uint8_t)str[len];
		if (c < 0x20 || c > 0x7E)
			return false;
		len++;
	}
	if (len < 2 || len > 4096)
		return false;
	if (str[len] != '\0')
		return false;

	// Skip MSVC RTTI mangled names — encrypting these breaks exception handling
	if (str[0] == '.' && str[1] == '?')
		return false;
	if (str[0] == '?' && str[1] == '?')
		return false;

	// Need: 4 key bytes + len string bytes + 1 null terminator
	if (string_area_offset + 4 + len + 1 > (kReservedPrefixSize - 0x100))
		return false;

	// Generate random 4-byte XOR key (each byte 1-255)
	std::random_device rd;
	std::default_random_engine generator(rd());
	std::uniform_int_distribution<int> distribution(1, 255);
	uint8_t key[4];
	for (int k = 0; k < 4; k++)
		key[k] = (uint8_t)distribution(generator);

	// Layout in string area: [4-byte key] [encrypted string bytes] [null]
	uint8_t* key_pos = base + new_section->VirtualAddress + string_area_offset;
	memcpy(key_pos, key, 4);

	uint8_t* dest = key_pos + 4;
	for (uint32_t i = 0; i < len; i++) {
		dest[i] = (uint8_t)str[i] ^ key[i % 4];
	}
	dest[len] = 0;  // null terminator NOT encrypted

	// Update location_of_data to point to the encrypted copy in .vmp0
	instruction->location_of_data = (uint64_t)dest;

	string_area_offset += 4 + len + 1;

	auto reg = x86_register_map->second;

	// Pick two callee-saved scratch registers that don't collide with reg
	// key_reg: holds the 4-byte rolling XOR key
	// cnt_reg: loop counter
	x86::Gp key64, key32, key8;
	if (reg.id() != x86::Gp::kIdBx) {
		key64 = x86::rbx; key32 = x86::ebx; key8 = x86::bl;
	} else {
		key64 = x86::r12; key32 = x86::r12d; key8 = x86::r12b;
	}

	x86::Gp cnt64, cnt32;
	if (reg.id() != x86::Gp::kIdR12 && key64.id() != x86::Gp::kIdR12) {
		cnt64 = x86::r12; cnt32 = x86::r12d;
	} else if (reg.id() != x86::Gp::kIdR13) {
		cnt64 = x86::r13; cnt32 = x86::r13d;
	} else {
		cnt64 = x86::r14; cnt32 = x86::r14d;
	}

	// Loop-based decrypt-once stub with 4-byte rolling XOR key:
	//   Load 4-byte key from [reg-4], zero it, then XOR each byte with
	//   the low byte of key, rotating key right by 8 after each byte.
	//   Second execution: key is 0, all XORs are no-ops.
	Label loop_start = assm.newLabel();
	Label loop_end = assm.newLabel();

	assm.pushf();
	assm.push(key64);
	assm.push(cnt64);
	assm.mov(key32, x86::dword_ptr(reg, -4));
	assm.mov(x86::dword_ptr(reg, -4), 0);
	assm.xor_(cnt64, cnt64);
	assm.bind(loop_start);
	assm.cmp(cnt32, len);
	assm.jge(loop_end);
	assm.xor_(x86::byte_ptr(reg, cnt64, 0), key8);
	assm.ror(key32, 8);
	assm.inc(cnt64);
	assm.jmp(loop_start);
	assm.bind(loop_end);
	assm.pop(cnt64);
	assm.pop(key64);
	assm.popf();

	void* fn;
	auto err = rt.add(&fn, &code);
	auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());

	for (auto jit : jitinstructions) {
		jit.isjmpcall = false;
		jit.has_relative = false;
		instruction = func->instructions.insert(instruction + 1, jit);
	}

	code.reset();
	code.init(rt.environment());
	code.attach(&this->assm);
	rt.release(fn);

	return true;
}
