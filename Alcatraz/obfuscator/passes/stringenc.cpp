#include "../obfuscator.h"

#include <random>

using namespace asmjit;

bool obfuscator::encrypt_strings(std::vector<obfuscator::function_t>::iterator& func, std::vector<obfuscator::instruction_t>::iterator& instruction, PIMAGE_SECTION_HEADER new_section) {

	// Only handle LEA with RIP-relative 32-bit displacement
	if (!instruction->has_relative || instruction->isjmpcall)
		return false;
	if (instruction->relative.size != 32)
		return false;

	auto base = pe->get_buffer()->data();

	// Check if location_of_data falls within .rdata
	auto rdata = pe->get_section(".rdata");
	if (!rdata)
		return false;

	uint64_t rdata_start = (uint64_t)base + rdata->VirtualAddress;
	uint64_t rdata_end = rdata_start + rdata->Misc.VirtualSize;
	uint64_t data_addr = instruction->location_of_data;

	if (data_addr < rdata_start || data_addr >= rdata_end)
		return false;

	// Validate: printable ASCII string, null-terminated, length 4-128
	const char* str = reinterpret_cast<const char*>(data_addr);
	uint32_t len = 0;
	while (len < 129 && str[len] != '\0') {
		uint8_t c = (uint8_t)str[len];
		if (c < 0x20 || c > 0x7E)
			return false;
		len++;
	}
	if (len < 4 || len > 128)
		return false;
	if (str[len] != '\0')
		return false;

	// Check room in string area (bytes 4 through 0xFFF of .0Dev)
	if (string_area_offset + len + 1 > 0x1000)
		return false;

	// Generate random XOR key (1-254)
	std::random_device rd;
	std::default_random_engine generator(rd());
	std::uniform_int_distribution<int> distribution(1, 254);
	uint8_t key = (uint8_t)distribution(generator);

	// Copy string to .0Dev string area and XOR encrypt
	uint8_t* dest = base + new_section->VirtualAddress + string_area_offset;
	for (uint32_t i = 0; i <= len; i++) {
		dest[i] = (uint8_t)str[i] ^ key;
	}

	// Update location_of_data to point to the encrypted copy in .0Dev
	instruction->location_of_data = (uint64_t)dest;

	uint32_t string_offset = string_area_offset;
	string_area_offset += len + 1;

	// Look up the destination register of the LEA
	auto x86_register_map = lookupmap.find(instruction->zyinstr.operands[0].reg.value);
	if (x86_register_map == lookupmap.end())
		return false;

	auto reg = x86_register_map->second;

	// Generate inline XOR decryption stub:
	// pushf
	// xor byte [reg+0], key
	// xor byte [reg+1], key
	// ...
	// xor byte [reg+len-1], key  (don't decrypt null terminator, just decrypt chars)
	// popf
	assm.pushf();
	for (uint32_t i = 0; i < len; i++) {
		assm.xor_(x86::byte_ptr(reg, (int)i), key);
	}
	assm.popf();

	void* fn;
	auto err = rt.add(&fn, &code);
	auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());

	for (auto jit : jitinstructions) {
		instruction = func->instructions.insert(instruction + 1, jit);
	}

	code.reset();
	code.init(rt.environment());
	code.attach(&this->assm);
	rt.release(fn);

	return true;
}
