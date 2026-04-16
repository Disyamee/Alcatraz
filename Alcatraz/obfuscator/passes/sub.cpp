#include "../obfuscator.h"

// SUB a, b  →  push b; not b; add a, b; pop b; add a, 1
// a + ~b + 1 = a + (-b) = a - b
bool obfuscator::obfuscate_sub(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (instruction->zyinstr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction->zyinstr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {

		if (instruction->zyinstr.operands[0].size < 32)
			return true;

		auto first_it = lookupmap.find(instruction->zyinstr.operands[0].reg.value);
		auto second_it = lookupmap.find(instruction->zyinstr.operands[1].reg.value);

		if (first_it == lookupmap.end() || second_it == lookupmap.end())
			return true;

		auto first = first_it->second;
		auto second = second_it->second;

		if (first == second)
			return true;

		if (first == x86::rsp || second == x86::rsp)
			return true;

		if (first.size() != second.size())
			return true;

		assm.push(second);
		assm.not_(second);
		assm.add(first, second);
		assm.pop(second);
		assm.add(first, 1);

		void* fn = nullptr;
		auto err = rt.add(&fn, &code);

		auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());
		int orig_id = instruction->inst_id;
		instruction = function->instructions.erase(instruction);
		instruction -= 1;
		jitinstructions.at(0).inst_id = orig_id;
		for (auto jit : jitinstructions) {
			instruction = function->instructions.insert(instruction + 1, jit);
		}

		code.reset();
		code.init(rt.environment());
		code.attach(&this->assm);
	}

	return true;
}
