#include "obfuscator.h"

#include <iostream>
#include <random>

ZydisFormatter formatter;
ZydisDecoder decoder;

int obfuscator::instruction_id = 0;
int obfuscator::function_iterator = 0;

obfuscator::obfuscator(pe64* pe) {

	this->pe = pe;
	this->total_size_used = 0;
	this->loadlib_iat_addr = 0;
	this->getproc_iat_addr = 0;
	this->string_area_offset = 4;
	instruction_id = 0;
	function_iterator = 0;

	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
		throw std::runtime_error("failed to init decoder");

	if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		throw std::runtime_error("failed to init formatter");

}

void obfuscator::create_functions(std::vector<pdbparser::sym_func>functions) {

	auto text_section = this->pe->get_section(".text");

	if (!text_section)
		throw std::runtime_error("couldn't find .text section");

	std::vector<uint32_t>visited_rvas;

	for (auto function : functions) {

		if (function.obfuscate == false)
			continue;
		if (std::find(visited_rvas.begin(), visited_rvas.end(), function.offset) != visited_rvas.end())
			continue;
		if (function.size < 5)
			continue;

		ZydisDisassembledInstruction zyinstruction{};

		auto address_to_analyze = this->pe->get_buffer()->data() + text_section->VirtualAddress + function.offset;
		uint32_t offset = 0;

		function_t new_function(function_iterator++, function.name, function.offset, function.size);

		new_function.ctfflattening = function.ctfflattening;
		new_function.movobf = function.movobf;
		new_function.mutateobf = function.mutateobf;
		new_function.leaobf = function.leaobf;
		new_function.antidisassembly = function.antidisassembly;
		new_function.iatobf = function.iatobf;
		new_function.stringenc = function.stringenc;

		std::vector <uint64_t> runtime_addresses;

		while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)(address_to_analyze + offset), (const void*)(address_to_analyze + offset), function.size - offset, &zyinstruction))) {

			instruction_t new_instruction{};
			new_instruction.runtime_address = (uint64_t)address_to_analyze + offset;
			new_instruction.load(new_function.func_id, zyinstruction, new_instruction.runtime_address);
			if (offset == 0)
				new_instruction.is_first_instruction = true;
			new_function.instructions.push_back(new_instruction);
			offset += new_instruction.zyinstr.info.length;

			uint64_t inst_index = new_function.instructions.size() - 1;
			this->runtime_addr_track[new_instruction.runtime_address].inst_index = inst_index;
			runtime_addresses.push_back(new_instruction.runtime_address);

			new_function.inst_id_index[new_instruction.inst_id] = inst_index;
		}

		visited_rvas.push_back(function.offset);
		this->functions.push_back(new_function);

		for (auto runtime_address = runtime_addresses.begin(); runtime_address != runtime_addresses.end(); ++runtime_address) {
			this->runtime_addr_track[*runtime_address].func_id = new_function.func_id;
		}
	}

}

void obfuscator::add_custom_entry(PIMAGE_SECTION_HEADER new_section) {

	if (pe->get_path().find(".exe") == std::string::npos)
		throw std::runtime_error("File type doesn't support custom entry!\n");

	auto nt = pe->get_nt();
	const uint32_t original_entry_rva = nt->OptionalHeader.AddressOfEntryPoint;

	// Strip security features that prevent execution from our new section:
	//   CFG (Control Flow Guard) — validates indirect branch targets; our stub would fail.
	//   Dynamic base is kept (ASLR works fine — we read actual base from PEB).
	nt->OptionalHeader.DllCharacteristics &= ~(USHORT)0x4000;  // IMAGE_DLLCHARACTERISTICS_GUARD_CF

	// Zero out the Load Config directory entry so the OS doesn't try to use
	// stale GuardCF tables that reference the old code layout.
	if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	}

	// Handcrafted x64 position-independent entry trampoline (21 bytes).
	// No asmjit, no CRT, no external calls, no RIP-relative addressing.
	//   mov rax, gs:[0x60]      ; TEB → PEB
	//   mov rax, [rax+0x10]     ; PEB → ImageBase
	//   add rax, <imm32>        ; + original entry RVA (sign-extended, always positive)
	//   jmp rax                 ; transfer control to real entry
	uint8_t stub[] = {
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[0x60]
		0x48, 0x8B, 0x40, 0x10,                                  // mov rax, [rax+0x10]
		0x48, 0x05, 0x00, 0x00, 0x00, 0x00,                      // add rax, imm32
		0xFF, 0xE0                                                // jmp rax
	};
	memcpy(&stub[15], &original_entry_rva, 4);

	printf("[ENTRY] Original EP RVA = 0x%08X\n", original_entry_rva);
	printf("[ENTRY] Stub placed at   .vmp0 + 0x%X  (RVA 0x%X)\n",
		this->total_size_used, new_section->VirtualAddress + this->total_size_used);
	printf("[ENTRY] Stub bytes (%zu):", sizeof(stub));
	for (size_t i = 0; i < sizeof(stub); i++) printf(" %02X", stub[i]);
	printf("\n");

	uint8_t* dest = pe->get_buffer()->data() + new_section->VirtualAddress + this->total_size_used;
	memcpy(dest, stub, sizeof(stub));

	nt->OptionalHeader.AddressOfEntryPoint = static_cast<uint32_t>(new_section->VirtualAddress + this->total_size_used);
	this->total_size_used += sizeof(stub);

	printf("[ENTRY] New EP RVA       = 0x%08X\n", nt->OptionalHeader.AddressOfEntryPoint);
}

bool obfuscator::find_inst_at_dst(uint64_t dst, instruction_t** instptr, function_t** funcptr) {

	if (this->runtime_addr_track.find(dst) != this->runtime_addr_track.end()) {
		*funcptr = &(this->functions[this->runtime_addr_track[dst].func_id]);

		if ((*funcptr)->has_jumptables)
			return false;

		*instptr = &(*funcptr)->instructions[this->runtime_addr_track[dst].inst_index];
		return true;
	}
	return false;
}

void obfuscator::remove_jumptables() {
	for (auto func = functions.begin(); func != functions.end(); func++) {
		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {
			if (instruction->has_relative && !instruction->isjmpcall && instruction->relative.size == 32) {

				auto relative_address = instruction->runtime_address + *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;

				if (relative_address == (uint64_t)this->pe->get_buffer()->data()) {
					func->has_jumptables = true;
					break;
				}
			}
		}
	}
}

bool obfuscator::analyze_functions() {

	this->remove_jumptables();

	for (auto func = functions.begin(); func != functions.end(); func++) {
		if (!func->has_jumptables) {
			for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

				if (instruction->has_relative) {

					if (instruction->isjmpcall) {

						uint64_t absolute_address = 0;

						if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction->zyinstr.info, &instruction->zyinstr.operands[0], instruction->runtime_address, (ZyanU64*) & absolute_address)))
							return false;

						obfuscator::instruction_t* instptr;
						obfuscator::function_t* funcptr;

						if (!this->find_inst_at_dst(absolute_address, &instptr, &funcptr)) {
							instruction->relative.target_inst_id = -1; //It doesnt jump to a func we relocate so we use absolute
							continue;
						}

						instruction->relative.target_inst_id = instptr->inst_id;
						instruction->relative.target_func_id = funcptr->func_id;
					}
					else {

						uint64_t original_data = instruction->runtime_address + instruction->zyinstr.info.length;

						switch (instruction->relative.size) {
						case 8:
							original_data += *(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						case 16:
							original_data += *(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						case 32:
							original_data += *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						}
						instruction->location_of_data = original_data;
					}
				}
			}
		}
	}

	return true;
}

void obfuscator::relocate(PIMAGE_SECTION_HEADER new_section) {

	auto base = pe->get_buffer()->data() + kReservedPrefixSize;

	uint32_t used_memory = 0;

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		uint32_t dst = new_section->VirtualAddress + used_memory;

		int instr_ctr = 0;

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {

			instruction->relocated_address = (uint64_t)base + dst + instr_ctr;
			instr_ctr += instruction->zyinstr.info.length;
		}

		used_memory += instr_ctr;
	}

	this->total_size_used = used_memory + kReservedPrefixSize;
}

bool obfuscator::find_instruction_by_id(int funcid, int instid, instruction_t* inst) {

	auto func = std::find_if(this->functions.begin(), this->functions.end(), [&](const obfuscator::function_t& func) {
		return func.func_id == funcid;
		});

	if (func == this->functions.end())
		return false;

	auto it = std::find_if(func->instructions.begin(), func->instructions.end(), [&](const obfuscator::instruction_t& inst) {
		return inst.inst_id == instid;
		});

	if (it != func->instructions.end())
	{
		*inst = *it;
		return true;

	}
	return false;
}

uint16_t rel8_to16(ZydisMnemonic mnemonic) {
	switch (mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
		return 0x870F;
	case ZYDIS_MNEMONIC_JB:
		return 0x820F;
	case ZYDIS_MNEMONIC_JBE:
		return 0x860F;
	case ZYDIS_MNEMONIC_JCXZ:
		return 0;
	case ZYDIS_MNEMONIC_JECXZ:
		return 0;
	case ZYDIS_MNEMONIC_JKNZD:
		return 0;
	case ZYDIS_MNEMONIC_JKZD:
		return 0;
	case ZYDIS_MNEMONIC_JL:
		return 0x8C0F;
	case ZYDIS_MNEMONIC_JLE:
		return 0x8E0F;
	case ZYDIS_MNEMONIC_JNB:
		return 0x830F;
	case ZYDIS_MNEMONIC_JNL:
		return 0x8D0F;
	case ZYDIS_MNEMONIC_JNLE:
		return 0x8F0F;
	case ZYDIS_MNEMONIC_JNO:
		return 0x810F;
	case ZYDIS_MNEMONIC_JNP:
		return 0x8B0F;
	case ZYDIS_MNEMONIC_JNS:
		return 0x890F;
	case ZYDIS_MNEMONIC_JNZ:
		return 0x850F;
	case ZYDIS_MNEMONIC_JO:
		return 0x800F;
	case ZYDIS_MNEMONIC_JP:
		return 0x8A0F;
	case ZYDIS_MNEMONIC_JRCXZ:
		return 0;
	case ZYDIS_MNEMONIC_JS:
		return 0x880F;
	case ZYDIS_MNEMONIC_JZ:
		return 0x840F;
	case ZYDIS_MNEMONIC_JMP:
		return 0xE990;
	default:
		break;
	}

	return 0;
}

bool obfuscator::fix_relative_jmps(function_t* func) {

	bool changed = true;
	while (changed) {
		changed = false;

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

			if (instruction->isjmpcall && instruction->relative.target_inst_id != -1) {

				instruction_t inst{};

				if (!this->find_instruction_by_id(instruction->relative.target_func_id, instruction->relative.target_inst_id, &inst)) {
					printf("[DEBUG] fix_relative_jmps FAIL: find_instruction_by_id failed\n");
					printf("  func='%s' func_id=%d inst_id=%d\n", func->name.c_str(), func->func_id, instruction->inst_id);
					printf("  target_func_id=%d target_inst_id=%d\n", instruction->relative.target_func_id, instruction->relative.target_inst_id);
					printf("  isjmpcall=%d has_relative=%d rel.size=%u rel.offset=%u\n", instruction->isjmpcall, instruction->has_relative, instruction->relative.size, instruction->relative.offset);
					printf("  raw_bytes[0..3]: %02X %02X %02X %02X  length=%d\n",
						instruction->raw_bytes.size() > 0 ? instruction->raw_bytes[0] : 0,
						instruction->raw_bytes.size() > 1 ? instruction->raw_bytes[1] : 0,
						instruction->raw_bytes.size() > 2 ? instruction->raw_bytes[2] : 0,
						instruction->raw_bytes.size() > 3 ? instruction->raw_bytes[3] : 0,
						instruction->zyinstr.info.length);
					instruction->print();
					return false;
				}


				switch (instruction->relative.size) {
				case 8: {
					signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length;
					if (distance > 127 || distance < -128) {

						if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JMP) {

							instruction->raw_bytes.resize(5);
							*(uint8_t*)(instruction->raw_bytes.data()) = 0xE9;
							*(int32_t*)(&instruction->raw_bytes.data()[1]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);

							instruction->reload();

							for (auto instruction2 = instruction; instruction2 != func->instructions.end(); instruction2++) {
								instruction2->relocated_address += 3;
							}

							changed = true;
							break;
						}
						else {

							uint16_t new_opcode = rel8_to16(instruction->zyinstr.info.mnemonic);

							if (new_opcode == 0) {
								printf("[DEBUG] fix_relative_jmps FAIL: rel8_to16 returned 0\n");
								printf("  func='%s' mnemonic=%d rel.size=%u\n", func->name.c_str(), instruction->zyinstr.info.mnemonic, instruction->relative.size);
								instruction->print();
								return false;
							}

							instruction->raw_bytes.resize(6);
							*(uint16_t*)(instruction->raw_bytes.data()) = new_opcode;
							*(int32_t*)(&instruction->raw_bytes.data()[2]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);

							instruction->reload();

							for (auto instruction2 = instruction; instruction2 != func->instructions.end(); ++instruction2) {
								instruction2->relocated_address += 4;
							}

							changed = true;
							break;
						}

					}
					break;
				}

				case 16: {
					signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length;
					if (distance > 32767 || distance < -32768)
					{
						printf("[DEBUG] fix_relative_jmps FAIL: rel16 out of range, distance=%d\n", distance);
						printf("  func='%s' inst_id=%d\n", func->name.c_str(), instruction->inst_id);
						instruction->print();
						return false;
					}
					break;
				}
				case 32: {
					break;
				}
				default:
				{
					printf("[DEBUG] fix_relative_jmps FAIL: unexpected rel.size=%u\n", instruction->relative.size);
					printf("  func='%s' inst_id=%d isjmpcall=%d has_relative=%d\n", func->name.c_str(), instruction->inst_id, instruction->isjmpcall, instruction->has_relative);
					printf("  target_func_id=%d target_inst_id=%d\n", instruction->relative.target_func_id, instruction->relative.target_inst_id);
					printf("  raw_bytes[0..5]: %02X %02X %02X %02X %02X %02X  length=%d\n",
						instruction->raw_bytes.size() > 0 ? instruction->raw_bytes[0] : 0,
						instruction->raw_bytes.size() > 1 ? instruction->raw_bytes[1] : 0,
						instruction->raw_bytes.size() > 2 ? instruction->raw_bytes[2] : 0,
						instruction->raw_bytes.size() > 3 ? instruction->raw_bytes[3] : 0,
						instruction->raw_bytes.size() > 4 ? instruction->raw_bytes[4] : 0,
						instruction->raw_bytes.size() > 5 ? instruction->raw_bytes[5] : 0,
						instruction->zyinstr.info.length);
					instruction->print();
					return false;
				}

				}

				if (changed)
					break;
			}
		}
	}
	return true;
}

bool obfuscator::convert_relative_jmps() {
	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		if (!this->fix_relative_jmps(&(*func))) {
			printf("[DEBUG] convert_relative_jmps failed on func '%s' (id=%d, %zu instructions)\n", func->name.c_str(), func->func_id, func->instructions.size());
			return false;
		}
	}
	return true;
}

bool obfuscator::apply_relocations(PIMAGE_SECTION_HEADER new_section) {

	this->relocate(new_section);

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {

			if (instruction->has_relative) {

				if (instruction->isjmpcall) {

					if (instruction->relative.target_inst_id == -1) { //Points without relocation

						switch (instruction->relative.size) {
						case 8: {
							uint64_t dst = instruction->runtime_address + *(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;
							*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						case 16: {
							uint64_t dst = instruction->runtime_address + *(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;
							*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						case 32: {
							uint64_t dst = instruction->runtime_address + *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;
							*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
					}
					else {

						instruction_t inst;
						if (!this->find_instruction_by_id(instruction->relative.target_func_id, instruction->relative.target_inst_id, &inst)) {
							return false;
						}

						switch (instruction->relative.size) {
						case 8: {
							*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						case 16:
							*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						case 32: {
							if (inst.is_first_instruction) //Jump to our stub in .text instead of relocated base
								*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(inst.runtime_address - instruction->relocated_address - instruction->zyinstr.info.length);
							else
								*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
					}

				}
				else {

					uint64_t dst = instruction->location_of_data;
					switch (instruction->relative.size) {
					case 8: {
						*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
						break;
					}
					case 16: {
						*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
						break;
					}
					case 32: {
						*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
						break;
					}
					default:
						return false;
					}

					memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
				}

			}
			else {
				memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
			}

		}
	}

	return true;
}

void obfuscator::compile(PIMAGE_SECTION_HEADER new_section) {

	const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(this->pe->get_nt());
	for (auto i = 0; i < this->pe->get_nt()->FileHeader.NumberOfSections; ++i) {
		current_image_section[i].PointerToRawData = current_image_section[i].VirtualAddress;
	}

	auto text_section = this->pe->get_section(".text");
	auto base = this->pe->get_buffer()->data();

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		auto first_instruction = func->instructions.begin();

		const uint8_t jmp_shell[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

		if (func->offset != -1) {
			uint32_t src = text_section->VirtualAddress + func->offset;
			uint32_t dst = first_instruction->relocated_address - (uint64_t)pe->get_buffer()->data();


			*(int32_t*)&jmp_shell[1] = (signed int)(dst - src - sizeof(jmp_shell));

			// Zero-fill original function body after the jmp trampoline
			memset((void*)((uint64_t)base + src + 5), 0, func->size - 5);

			memcpy((void*)(base + src), jmp_shell, sizeof(jmp_shell));
		}
	}

}

void obfuscator::run(PIMAGE_SECTION_HEADER new_section, bool obfuscate_entry_point) {

	if (!this->analyze_functions())
		throw std::runtime_error("couldn't analyze functions");

	this->build_iat_map();

	*(uint32_t*)(pe->get_buffer()->data() + new_section->VirtualAddress) = _rotl(pe->get_nt()->OptionalHeader.AddressOfEntryPoint, pe->get_nt()->FileHeader.TimeDateStamp) ^ pe->get_nt()->OptionalHeader.SizeOfStackCommit;

	code.init(rt.environment());
	code.attach(&this->assm);


	printf("OBFUSCATING: %i\n", functions.size());

	//Actual obfuscation passes

	for (auto func = functions.begin(); func != functions.end(); func++) {

		if (func->has_jumptables)
			continue;

		//Obfuscate control flow
		if (func->ctfflattening)
			this->flatten_control_flow(func);

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

			// Skip JIT-inserted stubs (e.g. string decrypt) — they must not be modified by other passes
			if (instruction->func_id < 0)
				continue;

			//Obfuscate IAT
			if (func->iatobf && instruction->isjmpcall && instruction->relative.target_inst_id == -1)
				this->obfuscate_iat_call(func, instruction);


			//Obfuscate 0xFF instructions to throw off disassemblers
			if (func->antidisassembly) {
				if (instruction->raw_bytes.data()[0] == 0xFF)
					this->obfuscate_ff(func, instruction);
			}


			//Obfuscate ADD
			if (func->mutateobf) {
				if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_ADD)
					this->obfuscate_add(func, instruction);
			}


			//String encryption (before LEA obfuscation)
			bool string_encrypted = false;
			if (func->stringenc && instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_LEA && instruction->has_relative) {
				string_encrypted = this->encrypt_strings(func, instruction, new_section);
			}

			//Obfuscate LEA
			if (func->leaobf && !string_encrypted) {
				if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_LEA && instruction->has_relative)
					this->obfuscsate_lea(func, instruction);
			}



			//Obfuscate MOV
			if (func->movobf) {
				if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_MOV)
				{
					int randnum = rand() % 3 + 1;
					int i = 0;
					while (this->obfuscate_mov(func, instruction) && i < randnum) {
						instruction -= 6;
						i++;
					}
				}
			}

			if (func->antidisassembly) {
				int randval = rand() % 20 + 1;

				if (randval == 1) {
					this->add_junk(func, instruction);
				}
			}


		}

	}

	this->relocate(new_section);

	if (!this->convert_relative_jmps())
		throw std::runtime_error("couldn't convert relative jmps");

	if (!this->apply_relocations(new_section))
		throw std::runtime_error("couldn't apply relocs");

	this->compile(new_section);

	if (!iat_patches.empty()) {
		this->write_iat_stubs(new_section);
		this->patch_iat_calls();
	}

	if (obfuscate_entry_point)
		this->add_custom_entry(new_section);

	// Fill unused .vmp0 space with random data for high entropy
	{
		auto base = pe->get_buffer()->data() + new_section->VirtualAddress;
		uint32_t section_capacity = new_section->Misc.VirtualSize;
		if (this->total_size_used < section_capacity) {
			std::mt19937 rng(std::random_device{}());
			uint8_t* fill_start = base + this->total_size_used;
			uint32_t fill_size = section_capacity - this->total_size_used;
			for (uint32_t i = 0; i < fill_size; i++)
				fill_start[i] = (uint8_t)(rng() % 256);
		}
	}

	// Anti-analysis: strip debug info, Rich header, and randomize timestamp
	pe->strip_debug_directory();
	pe->erase_rich_header();
	pe->randomize_timestamp();
}

uint32_t obfuscator::get_added_size() {
	return this->total_size_used;
}

std::vector<obfuscator::instruction_t>obfuscator::instructions_from_jit(uint8_t* code, uint32_t size) {

	std::vector<instruction_t>instructions;

	uint32_t offset = 0;
	ZydisDisassembledInstruction zyinstruction{};
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)(code + offset), (const void*)(code + offset), size - offset, &zyinstruction))) {

		instruction_t new_instruction{};
		new_instruction.load(-1, zyinstruction, (uint64_t)(code + offset));
		instructions.push_back(new_instruction);
		offset += new_instruction.zyinstr.info.length;
	}

	return instructions;
}

bool is_jmpcall(ZydisDecodedInstruction instr)
{
	switch (instr.mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_JMP:
	case ZYDIS_MNEMONIC_CALL:
		return true;
	default:
		return false;
	}
	return false;
}

void obfuscator::instruction_t::load_relative_info() {

	if (!(this->zyinstr.info.attributes & ZYDIS_ATTRIB_IS_RELATIVE))
	{
		this->relative.offset = 0; this->relative.size = 0; this->has_relative = false;
		return;
	}

	this->has_relative = true;
	this->isjmpcall = is_jmpcall(this->zyinstr.info);

	ZydisInstructionSegments segs;
	ZydisGetInstructionSegments(&this->zyinstr.info, &segs);
	for (uint8_t idx = 0; idx < this->zyinstr.info.operand_count; ++idx)
	{
		auto& op = this->zyinstr.operands[idx];


		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			if (op.imm.is_relative)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_IMMEDIATE)
					{
						this->relative.offset = this->zyinstr.info.raw.imm->offset;
						this->relative.size = this->zyinstr.info.raw.imm->size;
						break;
					}
				}
			}
		}
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			if (op.mem.base == ZYDIS_REGISTER_RIP)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_DISPLACEMENT)
					{
						this->relative.offset = this->zyinstr.info.raw.disp.offset;
						this->relative.size = this->zyinstr.info.raw.disp.size;
						break;
					}
				}
			}
		}
	}
}

void obfuscator::instruction_t::load(int funcid, std::vector<uint8_t>raw_data) {

	this->inst_id = instruction_id++;
	ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)raw_data.data(), (const void*)(raw_data.data()), raw_data.size(), &this->zyinstr);
	this->func_id = funcid;
	this->raw_bytes = raw_data;
	this->load_relative_info();
}
void obfuscator::instruction_t::load(int funcid, ZydisDisassembledInstruction zyinstruction, uint64_t runtime_address) {
	this->inst_id = instruction_id++;
	this->zyinstr = zyinstruction;
	this->func_id = funcid;
	this->raw_bytes.resize(this->zyinstr.info.length); memcpy(this->raw_bytes.data(), (void*)runtime_address, this->zyinstr.info.length);
	this->load_relative_info();
}

void obfuscator::instruction_t::reload() {
	ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)this->raw_bytes.data(), (const void*)this->raw_bytes.data(), this->raw_bytes.size(), &this->zyinstr);
	this->load_relative_info();
}

void obfuscator::instruction_t::print() {
	char buffer[256];
	ZydisFormatterFormatInstruction(&formatter, &this->zyinstr.info,this->zyinstr.operands,this->zyinstr.info.operand_count,
		buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
	puts(buffer);
}

std::unordered_map<ZydisRegister_, x86::Gp>obfuscator::lookupmap = {
	//8bit
	{ZYDIS_REGISTER_AL, x86::al},
	{ZYDIS_REGISTER_CL, x86::cl},
	{ZYDIS_REGISTER_DL, x86::dl},
	{ZYDIS_REGISTER_BL, x86::bl},
	{ZYDIS_REGISTER_AH, x86::ah},
	{ZYDIS_REGISTER_CH, x86::ch},
	{ZYDIS_REGISTER_DH, x86::dh},
	{ZYDIS_REGISTER_BH, x86::bh},
	{ZYDIS_REGISTER_SPL, x86::spl},
	{ZYDIS_REGISTER_BPL, x86::bpl},
	{ZYDIS_REGISTER_SIL, x86::sil},
	{ZYDIS_REGISTER_DIL, x86::dil},
	{ZYDIS_REGISTER_R8B, x86::r8b},
	{ZYDIS_REGISTER_R9B, x86::r9b},
	{ZYDIS_REGISTER_R10B, x86::r10b},
	{ZYDIS_REGISTER_R11B, x86::r11b},
	{ZYDIS_REGISTER_R12B, x86::r12b},
	{ZYDIS_REGISTER_R13B, x86::r13b},
	{ZYDIS_REGISTER_R14B, x86::r14b},
	{ZYDIS_REGISTER_R15B, x86::r15b},


	//16bit
	{ZYDIS_REGISTER_AX, x86::ax},
	{ZYDIS_REGISTER_CX, x86::cx},
	{ZYDIS_REGISTER_DX, x86::dx},
	{ZYDIS_REGISTER_BX, x86::bx},
	{ZYDIS_REGISTER_SP, x86::sp},
	{ZYDIS_REGISTER_BP, x86::bp},
	{ZYDIS_REGISTER_SI, x86::si},
	{ZYDIS_REGISTER_DI, x86::di},
	{ZYDIS_REGISTER_R8W, x86::r8w},
	{ZYDIS_REGISTER_R9W, x86::r9w},
	{ZYDIS_REGISTER_R10W, x86::r10w},
	{ZYDIS_REGISTER_R11W, x86::r11w},
	{ZYDIS_REGISTER_R12W, x86::r12w},
	{ZYDIS_REGISTER_R13W, x86::r13w},
	{ZYDIS_REGISTER_R14W, x86::r14w},
	{ZYDIS_REGISTER_R15W, x86::r15w},

	//32bit

	{ZYDIS_REGISTER_EAX, x86::eax},
	{ZYDIS_REGISTER_ECX, x86::ecx},
	{ZYDIS_REGISTER_EDX, x86::edx},
	{ZYDIS_REGISTER_EBX, x86::ebx},
	{ZYDIS_REGISTER_ESP, x86::esp},
	{ZYDIS_REGISTER_EBP, x86::ebp},
	{ZYDIS_REGISTER_ESI, x86::esi},
	{ZYDIS_REGISTER_EDI, x86::edi},
	{ZYDIS_REGISTER_R8D, x86::r8d},
	{ZYDIS_REGISTER_R9D, x86::r9d},
	{ZYDIS_REGISTER_R10D, x86::r10d},
	{ZYDIS_REGISTER_R11D, x86::r11d},
	{ZYDIS_REGISTER_R12D, x86::r12d},
	{ZYDIS_REGISTER_R13D, x86::r13d},
	{ZYDIS_REGISTER_R14D, x86::r14d},
	{ZYDIS_REGISTER_R15D, x86::r15d},

	//64bit

	{ZYDIS_REGISTER_RAX, x86::rax},
	{ZYDIS_REGISTER_RCX, x86::rcx},
	{ZYDIS_REGISTER_RDX, x86::rdx},
	{ZYDIS_REGISTER_RBX, x86::rbx},
	{ZYDIS_REGISTER_RSP, x86::rsp},
	{ZYDIS_REGISTER_RBP, x86::rbp},
	{ZYDIS_REGISTER_RSI, x86::rsi},
	{ZYDIS_REGISTER_RDI, x86::rdi},
	{ZYDIS_REGISTER_R8, x86::r8},
	{ZYDIS_REGISTER_R9, x86::r9},
	{ZYDIS_REGISTER_R10, x86::r10},
	{ZYDIS_REGISTER_R11, x86::r11},
	{ZYDIS_REGISTER_R12, x86::r12},
	{ZYDIS_REGISTER_R13, x86::r13},
	{ZYDIS_REGISTER_R14, x86::r14},
	{ZYDIS_REGISTER_R15, x86::r15}
};