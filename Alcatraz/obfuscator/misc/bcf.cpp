#include "../obfuscator.h"

#include <random>

bool obfuscator::insert_bogus_control_flow(std::vector<obfuscator::function_t>::iterator& func) {

	if (func->instructions.size() < 4)
		return true;

	std::random_device rd;
	std::mt19937 rng(rd());
	std::uniform_int_distribution<int> chance(1, 100);
	std::uniform_int_distribution<int> junk_count_dist(3, 6);
	std::uniform_int_distribution<uint32_t> imm_dist(1, 0x7FFFFFFF);

	const int max_insertions = 8;
	const int insertion_chance = 25;

	std::vector<int> insert_before_ids;

	for (size_t i = 1; i < func->instructions.size(); i++) {
		auto& inst = func->instructions[i];
		if (inst.func_id < 0) continue;
		if (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_RET) continue;

		auto& prev = func->instructions[i - 1];
		bool is_block_start = false;

		if (prev.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_RET) is_block_start = true;
		if (prev.isjmpcall && prev.zyinstr.info.mnemonic != ZYDIS_MNEMONIC_CALL) is_block_start = true;

		if (!is_block_start) {
			for (auto& other : func->instructions) {
				if (other.isjmpcall && other.relative.target_func_id == func->func_id &&
					other.relative.target_inst_id == inst.inst_id) {
					is_block_start = true;
					break;
				}
			}
		}

		if (is_block_start && chance(rng) <= insertion_chance) {
			insert_before_ids.push_back(inst.inst_id);
			if ((int)insert_before_ids.size() >= max_insertions)
				break;
		}
	}

	// Insert BCF block before each collected instruction
	for (auto target_id : insert_before_ids) {
		auto target_it = std::find_if(func->instructions.begin(), func->instructions.end(),
			[&](const obfuscator::instruction_t& inst) { return inst.inst_id == target_id; });

		if (target_it == func->instructions.end())
			continue;

		int real_target_inst_id = target_it->inst_id;
		uint32_t odd_value = imm_dist(rng) | 1;

		// Layout inserted before the real instruction:
		//   pushfq               ; save all flags
		//   push rcx             ; save rcx
		//   mov ecx, <odd>       ; ecx = guaranteed non-zero
		//   test ecx, ecx        ; ZF=0 (always)
		//   jz bogus_start       ; NEVER taken
		//   pop rcx              ; restore rcx   (real path)
		//   popfq                ; restore flags  (real path)
		//   jmp real_target      ; continue normally
		//   <bogus junk...>      ; dead code
		//   pop rcx              ; stack balance  (bogus path)
		//   popfq                ; stack balance  (bogus path)
		//   jmp real_target      ; safety net

		instruction_t inst_pushfq{};
		inst_pushfq.load(func->func_id, { 0x9C });
		inst_pushfq.is_synthetic = true;

		instruction_t inst_push_rcx{};
		inst_push_rcx.load(func->func_id, { 0x51 });
		inst_push_rcx.is_synthetic = true;

		instruction_t inst_mov_ecx{};
		inst_mov_ecx.load(func->func_id, { 0xB9,
			(uint8_t)(odd_value), (uint8_t)(odd_value >> 8),
			(uint8_t)(odd_value >> 16), (uint8_t)(odd_value >> 24) });
		inst_mov_ecx.is_synthetic = true;

		instruction_t inst_test{};
		inst_test.load(func->func_id, { 0x85, 0xC9 });
		inst_test.is_synthetic = true;

		instruction_t inst_jz{};
		inst_jz.load(func->func_id, { 0x74, 0x07 });
		inst_jz.is_synthetic = true;

		instruction_t inst_pop_rcx_real{};
		inst_pop_rcx_real.load(func->func_id, { 0x59 });
		inst_pop_rcx_real.is_synthetic = true;

		instruction_t inst_popfq_real{};
		inst_popfq_real.load(func->func_id, { 0x9D });
		inst_popfq_real.is_synthetic = true;

		instruction_t inst_jmp_real{};
		inst_jmp_real.load(func->func_id, { 0xE9, 0x00, 0x00, 0x00, 0x00 });
		inst_jmp_real.relative.target_func_id = func->func_id;
		inst_jmp_real.relative.target_inst_id = real_target_inst_id;
		inst_jmp_real.is_synthetic = true;

		std::vector<instruction_t> bogus_junk;
		int num_junk = junk_count_dist(rng);
		for (int j = 0; j < num_junk; j++) {
			instruction_t junk{};
			uint32_t imm = imm_dist(rng);
			switch (j % 4) {
			case 0:
				junk.load(func->func_id, { 0xB9, (uint8_t)(imm), (uint8_t)(imm >> 8), (uint8_t)(imm >> 16), (uint8_t)(imm >> 24) });
				break;
			case 1:
				junk.load(func->func_id, { 0x81, 0xC1, (uint8_t)(imm), (uint8_t)(imm >> 8), (uint8_t)(imm >> 16), (uint8_t)(imm >> 24) });
				break;
			case 2:
				junk.load(func->func_id, { 0x81, 0xF1, (uint8_t)(imm), (uint8_t)(imm >> 8), (uint8_t)(imm >> 16), (uint8_t)(imm >> 24) });
				break;
			case 3:
				junk.load(func->func_id, { 0x81, 0xE9, (uint8_t)(imm), (uint8_t)(imm >> 8), (uint8_t)(imm >> 16), (uint8_t)(imm >> 24) });
				break;
			}
			junk.is_synthetic = true;
			bogus_junk.push_back(junk);
		}

		instruction_t inst_pop_rcx_bogus{};
		inst_pop_rcx_bogus.load(func->func_id, { 0x59 });
		inst_pop_rcx_bogus.is_synthetic = true;

		instruction_t inst_popfq_bogus{};
		inst_popfq_bogus.load(func->func_id, { 0x9D });
		inst_popfq_bogus.is_synthetic = true;

		instruction_t inst_jmp_bogus{};
		inst_jmp_bogus.load(func->func_id, { 0xE9, 0x00, 0x00, 0x00, 0x00 });
		inst_jmp_bogus.relative.target_func_id = func->func_id;
		inst_jmp_bogus.relative.target_inst_id = real_target_inst_id;
		inst_jmp_bogus.is_synthetic = true;

		// Remember IDs before insertion (vector will reallocate)
		int jz_id = inst_jz.inst_id;
		int first_bogus_id = bogus_junk[0].inst_id;

		// Insert all instructions before the real target
		auto pos = target_it;

		pos = func->instructions.insert(pos, inst_pushfq); pos++;
		pos = func->instructions.insert(pos, inst_push_rcx); pos++;
		pos = func->instructions.insert(pos, inst_mov_ecx); pos++;
		pos = func->instructions.insert(pos, inst_test); pos++;
		pos = func->instructions.insert(pos, inst_jz); pos++;
		pos = func->instructions.insert(pos, inst_pop_rcx_real); pos++;
		pos = func->instructions.insert(pos, inst_popfq_real); pos++;
		pos = func->instructions.insert(pos, inst_jmp_real); pos++;

		for (auto& junk : bogus_junk) {
			pos = func->instructions.insert(pos, junk); pos++;
		}
		pos = func->instructions.insert(pos, inst_pop_rcx_bogus); pos++;
		pos = func->instructions.insert(pos, inst_popfq_bogus); pos++;
		pos = func->instructions.insert(pos, inst_jmp_bogus);

		// Fix JZ target → first bogus instruction
		auto jz_it = std::find_if(func->instructions.begin(), func->instructions.end(),
			[&](const obfuscator::instruction_t& inst) { return inst.inst_id == jz_id; });

		if (jz_it != func->instructions.end()) {
			jz_it->relative.target_func_id = func->func_id;
			jz_it->relative.target_inst_id = first_bogus_id;
		}
	}

	return true;
}
