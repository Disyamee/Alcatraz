#include "../obfuscator.h"

#include <algorithm>
#include <random>

void obfuscator::build_iat_map() {
	auto nt = pe->get_nt();
	auto base = pe->get_buffer()->data();
	auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
		return;

	auto import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + import_dir.VirtualAddress);

	loadlib_iat_addr = 0;
	getproc_iat_addr = 0;

	while (import_desc->Name != 0) {
		const char* dll_name = reinterpret_cast<const char*>(base + import_desc->Name);

		auto oft = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->OriginalFirstThunk);
		auto ft = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->FirstThunk);

		while (oft->u1.AddressOfData != 0) {
			if (!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
				auto hint_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + oft->u1.AddressOfData);
				const char* func_name = hint_name->Name;

				iat_entry_t entry{};
				entry.buffer_address = (uint64_t)&ft->u1.Function;
				entry.dll_name = dll_name;
				entry.func_name = func_name;
				entry.stub_address = 0;

				if (std::string(func_name) == "LoadLibraryA" && loadlib_iat_addr == 0)
					loadlib_iat_addr = entry.buffer_address;
				if (std::string(func_name) == "GetProcAddress" && getproc_iat_addr == 0)
					getproc_iat_addr = entry.buffer_address;

				iat_map.push_back(entry);
			}
			oft++;
			ft++;
		}
		import_desc++;
	}
}

bool obfuscator::obfuscate_iat_call(std::vector<obfuscator::function_t>::iterator& func, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	// Need both LoadLibraryA and GetProcAddress in the IAT
	if (loadlib_iat_addr == 0 || getproc_iat_addr == 0)
		return true;

	// Only handle FF 15 (CALL [rip+disp32]) and FF 25 (JMP [rip+disp32])
	if (instruction->raw_bytes.size() < 6)
		return true;

	uint8_t b0 = instruction->raw_bytes[0];
	uint8_t b1 = instruction->raw_bytes[1];

	bool is_call = false;
	if (b0 == 0xFF && b1 == 0x15) {
		is_call = true;
	} else if (b0 == 0xFF && b1 == 0x25) {
		is_call = false;
	} else {
		return true;
	}

	// Compute the target IAT slot address in the PE buffer
	int32_t disp = *(int32_t*)(&instruction->raw_bytes[2]);
	uint64_t iat_slot_addr = instruction->runtime_address + instruction->zyinstr.info.length + disp;

	// Look up in our IAT map
	int found_index = -1;
	for (int i = 0; i < (int)iat_map.size(); i++) {
		if (iat_map[i].buffer_address == iat_slot_addr) {
			found_index = i;
			break;
		}
	}

	if (found_index == -1)
		return true;

	// Don't obfuscate LoadLibraryA and GetProcAddress — our stubs need them
	auto& entry = iat_map[found_index];
	if (entry.func_name == "LoadLibraryA" || entry.func_name == "GetProcAddress")
		return true;

	// Build replacement: CALL/JMP rel32 placeholder (5 bytes)
	std::vector<uint8_t> call_bytes = {(uint8_t)(is_call ? 0xE8 : 0xE9), 0x00, 0x00, 0x00, 0x00};

	int original_inst_id = instruction->inst_id;

	instruction_t new_inst{};
	new_inst.load(func->func_id, call_bytes);
	new_inst.inst_id = original_inst_id;
	new_inst.has_relative = false;
	new_inst.isjmpcall = false;
	new_inst.is_first_instruction = instruction->is_first_instruction;

	// Record for post-compilation patching
	iat_patch_t patch{};
	patch.func_id = func->func_id;
	patch.inst_id = new_inst.inst_id;
	patch.iat_index = found_index;
	patch.is_call = is_call;
	iat_patches.push_back(patch);

	// Replace original instruction (single instruction, no insertion needed)
	*instruction = new_inst;

	return true;
}

void obfuscator::write_iat_stubs(PIMAGE_SECTION_HEADER new_section) {
	auto base = pe->get_buffer()->data();

	// Determine which IAT entries need stubs
	std::vector<bool> needs_stub(iat_map.size(), false);
	for (auto& patch : iat_patches) {
		needs_stub[patch.iat_index] = true;
	}

	std::random_device rd;
	std::default_random_engine rng(rd());
	std::uniform_int_distribution<int> key_dist(1, 255);

	for (size_t i = 0; i < iat_map.size(); i++) {
		if (!needs_stub[i]) continue;

		auto& entry = iat_map[i];

		uint32_t dll_name_len = (uint32_t)entry.dll_name.size();
		uint32_t func_name_len = (uint32_t)entry.func_name.size();

		// Generate 4-byte XOR keys (no zero bytes)
		uint8_t dll_key[4], func_key[4];
		for (int k = 0; k < 4; k++) {
			dll_key[k] = (uint8_t)key_dist(rng);
			func_key[k] = (uint8_t)key_dist(rng);
		}
		uint32_t dll_key32, func_key32;
		memcpy(&dll_key32, dll_key, 4);
		memcpy(&func_key32, func_key, 4);

		// Stub layout with inline string decryption:
		//
		// [0]   mov rax, [rip+127]           7   → cached_ptr at 134
		// [7]   test rax, rax                3
		// [10]  jnz +120                     2   → go at 132
		// [12]  push rcx                     1
		// [13]  push rdx                     1
		// [14]  push r8                      2
		// [16]  push r9                      2
		// [18]  sub rsp, 0x28                4
		//
		// --- Decrypt dll_name (4-byte rolling XOR) ---
		// [22]  lea r10, [rip+113]           7   → dll_name at 142
		// [29]  mov ecx, dll_len             5
		// [34]  mov r11d, dll_key32          6
		// .dll_loop:
		// [40]  xor byte [r10], r11b         3
		// [43]  ror r11d, 8                  4
		// [47]  inc r10                      3
		// [50]  dec ecx                      2
		// [52]  jnz .dll_loop                2   (disp = -14)
		//
		// --- Call LoadLibraryA ---
		// [54]  lea rcx, [rip+81]            7   → dll_name at 142
		// [61]  call [rip+X_LL]              6   → LoadLibraryA IAT
		//
		// --- Decrypt func_name (4-byte rolling XOR) ---
		// [67]  lea r10, [rip+F]             7   → func_name at 142+dll_len+1
		// [74]  mov ecx, func_len            5
		// [79]  mov r11d, func_key32         6
		// .func_loop:
		// [85]  xor byte [r10], r11b         3
		// [88]  ror r11d, 8                  4
		// [92]  inc r10                      3
		// [95]  dec ecx                      2
		// [97]  jnz .func_loop              2   (disp = -14)
		//
		// --- Call GetProcAddress ---
		// [99]  mov rcx, rax                 3
		// [102] lea rdx, [rip+F2]            7   → func_name
		// [109] call [rip+X_GP]              6   → GetProcAddress IAT
		//
		// --- Cache and return ---
		// [115] mov [rip+12], rax            7   → cached_ptr at 134
		// [122] add rsp, 0x28                4
		// [126] pop r9                       2
		// [128] pop r8                       2
		// [130] pop rdx                      1
		// [131] pop rcx                      1
		// go:
		// [132] jmp rax                      2
		//
		// --- data ---
		// [134] cached_ptr: dq 0             8
		// [142] dll_name: XOR'd              dll_len+1
		// [142+dll_len+1] func_name: XOR'd   func_len+1

		const uint32_t CODE_SIZE = 134;
		const uint32_t DATA_OFFSET = CODE_SIZE;        // 134
		const uint32_t DLL_OFFSET = DATA_OFFSET + 8;   // 142
		const uint32_t FUNC_OFFSET = DLL_OFFSET + dll_name_len + 1;
		uint32_t stub_size = FUNC_OFFSET + func_name_len + 1;

		uint64_t stub_addr = (uint64_t)(base + new_section->VirtualAddress + total_size_used);

		// External IAT slot displacements (from end of CALL instruction)
		int32_t X_LL = (int32_t)((int64_t)loadlib_iat_addr - (int64_t)(stub_addr + 67));
		int32_t X_GP = (int32_t)((int64_t)getproc_iat_addr - (int64_t)(stub_addr + 115));

		std::vector<uint8_t> stub(stub_size, 0);
		int p = 0;

		// [0] mov rax, [rip+127]  →  cached_ptr at 134
		stub[p++] = 0x48; stub[p++] = 0x8B; stub[p++] = 0x05;
		*(int32_t*)&stub[p] = (int32_t)(DATA_OFFSET - 7); p += 4;  // 134 - 7 = 127

		// [7] test rax, rax
		stub[p++] = 0x48; stub[p++] = 0x85; stub[p++] = 0xC0;

		// [10] jnz go  (go at 132, disp = 132 - 12 = 120)
		stub[p++] = 0x75; stub[p++] = (uint8_t)(132 - 12);

		// [12] push rcx
		stub[p++] = 0x51;
		// [13] push rdx
		stub[p++] = 0x52;
		// [14] push r8
		stub[p++] = 0x41; stub[p++] = 0x50;
		// [16] push r9
		stub[p++] = 0x41; stub[p++] = 0x51;
		// [18] sub rsp, 0x28
		stub[p++] = 0x48; stub[p++] = 0x83; stub[p++] = 0xEC; stub[p++] = 0x28;

		// --- Decrypt dll_name ---
		// [22] lea r10, [rip+113]  →  dll_name at 142
		stub[p++] = 0x4C; stub[p++] = 0x8D; stub[p++] = 0x15;
		*(int32_t*)&stub[p] = (int32_t)(DLL_OFFSET - 29); p += 4;  // 142 - 29 = 113

		// [29] mov ecx, dll_len
		stub[p++] = 0xB9;
		*(uint32_t*)&stub[p] = dll_name_len; p += 4;

		// [34] mov r11d, dll_key32
		stub[p++] = 0x41; stub[p++] = 0xBB;
		*(uint32_t*)&stub[p] = dll_key32; p += 4;

		// .dll_loop: (offset 40)
		// [40] xor byte [r10], r11b
		stub[p++] = 0x45; stub[p++] = 0x30; stub[p++] = 0x1A;
		// [43] ror r11d, 8
		stub[p++] = 0x41; stub[p++] = 0xC1; stub[p++] = 0xCB; stub[p++] = 0x08;
		// [47] inc r10
		stub[p++] = 0x49; stub[p++] = 0xFF; stub[p++] = 0xC2;
		// [50] dec ecx
		stub[p++] = 0xFF; stub[p++] = 0xC9;
		// [52] jnz .dll_loop  (disp = 40 - 54 = -14)
		stub[p++] = 0x75; stub[p++] = 0xF2;

		// --- Call LoadLibraryA ---
		// [54] lea rcx, [rip+81]  →  dll_name at 142
		stub[p++] = 0x48; stub[p++] = 0x8D; stub[p++] = 0x0D;
		*(int32_t*)&stub[p] = (int32_t)(DLL_OFFSET - 61); p += 4;  // 142 - 61 = 81

		// [61] call [rip+X_LL]  →  LoadLibraryA
		stub[p++] = 0xFF; stub[p++] = 0x15;
		*(int32_t*)&stub[p] = X_LL; p += 4;

		// --- Decrypt func_name ---
		// [67] lea r10, [rip+F]  →  func_name
		stub[p++] = 0x4C; stub[p++] = 0x8D; stub[p++] = 0x15;
		*(int32_t*)&stub[p] = (int32_t)(FUNC_OFFSET - 74); p += 4;  // (142+dll_len+1) - 74

		// [74] mov ecx, func_len
		stub[p++] = 0xB9;
		*(uint32_t*)&stub[p] = func_name_len; p += 4;

		// [79] mov r11d, func_key32
		stub[p++] = 0x41; stub[p++] = 0xBB;
		*(uint32_t*)&stub[p] = func_key32; p += 4;

		// .func_loop: (offset 85)
		// [85] xor byte [r10], r11b
		stub[p++] = 0x45; stub[p++] = 0x30; stub[p++] = 0x1A;
		// [88] ror r11d, 8
		stub[p++] = 0x41; stub[p++] = 0xC1; stub[p++] = 0xCB; stub[p++] = 0x08;
		// [92] inc r10
		stub[p++] = 0x49; stub[p++] = 0xFF; stub[p++] = 0xC2;
		// [95] dec ecx
		stub[p++] = 0xFF; stub[p++] = 0xC9;
		// [97] jnz .func_loop  (disp = 85 - 99 = -14)
		stub[p++] = 0x75; stub[p++] = 0xF2;

		// --- Call GetProcAddress ---
		// [99] mov rcx, rax
		stub[p++] = 0x48; stub[p++] = 0x89; stub[p++] = 0xC1;

		// [102] lea rdx, [rip+F2]  →  func_name
		stub[p++] = 0x48; stub[p++] = 0x8D; stub[p++] = 0x15;
		*(int32_t*)&stub[p] = (int32_t)(FUNC_OFFSET - 109); p += 4;  // (142+dll_len+1) - 109

		// [109] call [rip+X_GP]  →  GetProcAddress
		stub[p++] = 0xFF; stub[p++] = 0x15;
		*(int32_t*)&stub[p] = X_GP; p += 4;

		// --- Cache and return ---
		// [115] mov [rip+12], rax  →  cached_ptr at 134
		stub[p++] = 0x48; stub[p++] = 0x89; stub[p++] = 0x05;
		*(int32_t*)&stub[p] = (int32_t)(DATA_OFFSET - 122); p += 4;  // 134 - 122 = 12

		// [122] add rsp, 0x28
		stub[p++] = 0x48; stub[p++] = 0x83; stub[p++] = 0xC4; stub[p++] = 0x28;

		// [126] pop r9
		stub[p++] = 0x41; stub[p++] = 0x59;
		// [128] pop r8
		stub[p++] = 0x41; stub[p++] = 0x58;
		// [130] pop rdx
		stub[p++] = 0x5A;
		// [131] pop rcx
		stub[p++] = 0x59;

		// [132] jmp rax  (go label)
		stub[p++] = 0xFF; stub[p++] = 0xE0;

		// p = 134 = CODE_SIZE
		// [134] cached_ptr = 0 (already zeroed)
		p = DLL_OFFSET;  // 142

		// [142] dll_name — XOR encrypted with rolling 4-byte key
		for (uint32_t j = 0; j < dll_name_len; j++) {
			stub[p++] = (uint8_t)entry.dll_name[j] ^ dll_key[j % 4];
		}
		stub[p++] = 0;  // null terminator (not encrypted)

		// func_name — XOR encrypted with rolling 4-byte key
		for (uint32_t j = 0; j < func_name_len; j++) {
			stub[p++] = (uint8_t)entry.func_name[j] ^ func_key[j % 4];
		}
		stub[p++] = 0;  // null terminator

		entry.stub_address = stub_addr;
		memcpy((void*)stub_addr, stub.data(), stub.size());
		total_size_used += stub_size;
	}
}

void obfuscator::patch_iat_calls() {
	for (auto& patch : iat_patches) {
		auto& entry = iat_map[patch.iat_index];

		for (auto& func : functions) {
			if (func.func_id != patch.func_id)
				continue;

			for (auto& inst : func.instructions) {
				if (inst.inst_id != patch.inst_id)
					continue;

				// Instruction is 5 bytes: E8/E9 [rel32]
				uint64_t call_end = inst.relocated_address + 5;
				int32_t rel = (int32_t)((int64_t)entry.stub_address - (int64_t)call_end);
				*(int32_t*)(inst.relocated_address + 1) = rel;
				goto next_patch;
			}
		}
		next_patch:;
	}
}
