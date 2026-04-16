#include "../obfuscator.h"

#include <random>

bool obfuscator::hide_call(std::vector<obfuscator::function_t>::iterator& func, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (instruction->raw_bytes.size() < 5)
		return true;

	if (instruction->raw_bytes[0] != 0xE8)
		return true;

	if (!instruction->isjmpcall || !instruction->has_relative)
		return true;

	if (instruction->relative.target_inst_id == -1)
		return true;

	// Find target instruction to verify it's the first instruction of a function
	instruction_t target_inst;
	if (!this->find_instruction_by_id(instruction->relative.target_func_id, instruction->relative.target_inst_id, &target_inst))
		return true;

	if (!target_inst.is_first_instruction)
		return true;

	// Replace with CALL rel32 placeholder — post-compilation patching will fill it
	std::vector<uint8_t> call_bytes = { 0xE8, 0x00, 0x00, 0x00, 0x00 };

	int original_inst_id = instruction->inst_id;
	bool was_first = instruction->is_first_instruction;

	instruction_t new_inst{};
	new_inst.load(func->func_id, call_bytes);
	new_inst.inst_id = original_inst_id;
	new_inst.has_relative = false;
	new_inst.isjmpcall = false;
	new_inst.is_first_instruction = was_first;

	call_hide_patch_t patch{};
	patch.func_id = func->func_id;
	patch.inst_id = new_inst.inst_id;
	patch.target_runtime_addr = target_inst.runtime_address;
	call_hide_patches.push_back(patch);

	*instruction = new_inst;

	return true;
}

void obfuscator::write_call_hide_stubs(PIMAGE_SECTION_HEADER new_section) {
	auto base = pe->get_buffer()->data();

	std::random_device rd;
	std::default_random_engine rng(rd());

	for (auto& patch : call_hide_patches) {
		uint64_t call_relocated = 0;
		for (auto& func : functions) {
			if (func.func_id != patch.func_id) continue;
			for (auto& inst : func.instructions) {
				if (inst.inst_id != patch.inst_id) continue;
				call_relocated = inst.relocated_address;
				goto found_call;
			}
		}
		continue;

	found_call:
		uint64_t stub_addr = (uint64_t)(base + new_section->VirtualAddress + total_size_used);

		// Stub (32 bytes):
		//   [0]  push rax                  1   50
		//   [1]  push rcx                  1   51
		//   [2]  lea rax, [rip+0]          7   48 8D 05 00 00 00 00  → rax = stub+9
		//   [9]  mov ecx, ENCRYPTED        5   B9 xx xx xx xx
		//   [14] xor ecx, KEY              6   81 F1 xx xx xx xx
		//   [20] movsxd rcx, ecx           3   48 63 C9
		//   [23] add rax, rcx              3   48 01 C8
		//   [26] pop rcx                   1   59
		//   [27] xchg [rsp], rax           4   48 87 04 24
		//   [31] ret                       1   C3
		//
		// After CALL stub: stack = [ret_addr]
		// push rax/rcx:   stack = [rcx][rax][ret_addr]
		// compute rax = target
		// pop rcx:        stack = [rax_saved][ret_addr]
		// xchg [rsp],rax: stack = [target][ret_addr], rax restored
		// ret:            pops target, jumps there. stack = [ret_addr]
		// → target function runs, RETs to original return address

		int32_t real_disp = (int32_t)((int64_t)patch.target_runtime_addr - (int64_t)(stub_addr + 9));
		uint32_t key = (uint32_t)(rng());
		if (key == 0) key = 0xDEADBEEF;
		uint32_t encrypted_disp = (uint32_t)real_disp ^ key;

		uint8_t stub[32];
		int p = 0;

		stub[p++] = 0x50;                                               // push rax
		stub[p++] = 0x51;                                               // push rcx
		stub[p++] = 0x48; stub[p++] = 0x8D; stub[p++] = 0x05;         // lea rax, [rip+0]
		*(int32_t*)&stub[p] = 0; p += 4;
		stub[p++] = 0xB9;                                               // mov ecx, ENCRYPTED
		*(uint32_t*)&stub[p] = encrypted_disp; p += 4;
		stub[p++] = 0x81; stub[p++] = 0xF1;                            // xor ecx, KEY
		*(uint32_t*)&stub[p] = key; p += 4;
		stub[p++] = 0x48; stub[p++] = 0x63; stub[p++] = 0xC9;         // movsxd rcx, ecx
		stub[p++] = 0x48; stub[p++] = 0x01; stub[p++] = 0xC8;         // add rax, rcx
		stub[p++] = 0x59;                                               // pop rcx
		stub[p++] = 0x48; stub[p++] = 0x87; stub[p++] = 0x04; stub[p++] = 0x24;  // xchg [rsp], rax
		stub[p++] = 0xC3;                                               // ret

		// Patch the CALL to point to this stub
		uint64_t call_end = call_relocated + 5;
		int32_t rel = (int32_t)((int64_t)stub_addr - (int64_t)call_end);
		*(int32_t*)(call_relocated + 1) = rel;

		memcpy((void*)stub_addr, stub, sizeof(stub));
		total_size_used += sizeof(stub);
	}
}
